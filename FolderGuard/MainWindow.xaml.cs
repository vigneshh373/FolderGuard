using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using FolderGuard.Models;
using FolderGuard.Services;
using FolderGuard.ViewModels;
using FolderGuard.Views;
using Microsoft.Win32;

namespace FolderGuard;

public partial class MainWindow : Window
{
    private readonly AppOptions _options;
    private readonly Logger _logger;
    private readonly ConfigurationService _configuration;
    private readonly JournalStore _journal;
    private readonly FolderProtectionService _protection;
    private readonly RecoveryService _recovery;
    private readonly ObservableCollection<FolderItemViewModel> _items = new();

    private readonly DispatcherTimer _monitor = new() { Interval = TimeSpan.FromSeconds(10) };
    private readonly TimeSpan _autoLockIdleTimeout;
    private readonly Dictionary<string, ProtectionState> _lastKnownStates = new(StringComparer.Ordinal);

    private FolderItemViewModel? _selected;
    private string? _chosenPath;

    public MainWindow()
    {
        InitializeComponent();

        _options = AppOptions.Load();
        _autoLockIdleTimeout = TimeSpan.FromMinutes(Math.Max(1, _options.AutoLockIdleMinutes));

        var dataDirectory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            _options.DataDirectoryName);

        _logger = new Logger(Path.Combine(dataDirectory, "logs"));
        _configuration = new ConfigurationService(_options, _logger, dataDirectory);
        _journal = new JournalStore(_configuration.JournalDirectory, _logger);
        _protection = new FolderProtectionService(_configuration, _journal, _logger);
        _recovery = new RecoveryService(_configuration, _protection, _journal, _logger);

        FolderList.ItemsSource = _items;

        Setup.BrowseRequested += (_, _) => BrowseForFolder();
        Setup.ProtectRequested += (_, _) => ProtectChosenFolder();
        Settings.OpenDataFolderRequested += (_, _) => OpenDataFolder();
        Settings.ReloadRequested += (_, _) => ReloadConfiguration();
        Settings.LockAllRequested += (_, _) => LockAll();
        Settings.RepairRequested += (_, _) => RepairAll();

        Loaded += MainWindow_Loaded;
        Activated += (_, _) => CheckForPermissionChanges(reportTampering: true);
        _monitor.Tick += (_, _) =>
        {
            CheckForPermissionChanges(reportTampering: true);
            AutoLockIfIdle();
        };
        _monitor.Start();
    }

    // ---------------------------------------------------------------- startup

    private void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        AdminChip.Text = AclManager.IsElevated() ? "Administrator" : "Not elevated";
        Settings.Initialise(_configuration.DataDirectory);
        Setup.SetHint(
            "The folder stays visible in File Explorer. Only access to its contents is denied.",
            isError: false);

        if (_configuration.LoadStatus == ConfigurationLoadStatus.Failed)
        {
            ShowBanner(_configuration.LoadError ?? "The configuration store could not be read.");
            Setup.SetEnabledState(false);
            RefreshFolderList();
            SetStatus("Configuration unavailable — no folder permissions were changed.");
            return;
        }

        if (!string.IsNullOrEmpty(App.PrivilegeWarning))
            ShowBanner(App.PrivilegeWarning);

        var report = _recovery.Run();
        if (report.Messages.Count > 0)
            ShowBanner(report.Messages.Count > 0 && !string.IsNullOrEmpty(App.PrivilegeWarning)
                ? App.PrivilegeWarning + " " + report.Summary
                : report.Summary);

        RefreshFolderList();

        SetStatus(report.RepairedFolders
            ? "Startup recovery re-locked protected folders."
            : "Ready.");
    }

    // ---------------------------------------------------------------- folder selection

    private void BrowseForFolder()
    {
        var dialog = new OpenFolderDialog
        {
            Title = "Choose a folder to protect",
            Multiselect = false
        };

        if (dialog.ShowDialog(this) != true)
            return;

        if (!AclManager.ValidateFolder(dialog.FolderName, out var normalized, out var error))
        {
            _chosenPath = null;
            Setup.SetPath(null);
            Setup.SetHint(error, isError: true);
            SetStatus("That folder cannot be protected.");
            return;
        }

        var existing = _configuration.FindByPath(normalized);
        if (existing is not null)
        {
            _chosenPath = null;
            Setup.SetPath(normalized);
            Setup.SetHint("This folder is already protected. Select it in the list to manage it.", isError: true);
            SelectFolder(existing.Id);
            return;
        }

        _chosenPath = normalized;
        Setup.SetPath(normalized);
        Setup.SetHint("Press Protect Folder, then confirm the folder and create its password.", isError: false);
        SetStatus("Folder selected: " + normalized);
    }

    private void ProtectChosenFolder()
    {
        if (_chosenPath is null)
        {
            SetStatus("Choose a folder first.");
            return;
        }

        if (_configuration.LoadStatus == ConfigurationLoadStatus.Failed)
        {
            MessageBox.Show(
                this,
                "The configuration store cannot be read, so protection is disabled to avoid losing the permission backups.",
                "FolderGuard",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        var dialog = new ProtectFolderDialog(_chosenPath) { Owner = this };
        if (dialog.ShowDialog() != true)
            return;

        var result = _protection.Protect(_chosenPath, dialog.Password, dialog.Password);

        if (!result.Success)
        {
            SetStatus("Protection failed.");
            MessageBox.Show(this, result.Message, "FolderGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
            RefreshFolderList();
            return;
        }

        _chosenPath = null;
        Setup.SetPath(null);
        Setup.SetHint(
            "The folder stays visible in File Explorer. Only access to its contents is denied.",
            isError: false);

        RefreshFolderList(_configuration.Configuration.Settings.LastSelectedFolderId);
        SetStatus(result.Message);

        MessageBox.Show(
            this,
            result.Message + "\n\nKeep the password safe: it cannot be recovered.",
            "Folder protected",
            MessageBoxButton.OK,
            MessageBoxImage.Information);
    }

    // ---------------------------------------------------------------- selected folder

    private void FolderList_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        UpdateSelection();
    }

    private void UpdateSelection()
    {
        _selected = FolderList.SelectedItem as FolderItemViewModel;
        FolderPassword.Clear();
        ActionMessage.Visibility = Visibility.Collapsed;

        if (_selected is null)
        {
            NoSelection.Visibility = Visibility.Visible;
            ActionsPanel.Visibility = Visibility.Collapsed;
            SelectedName.Visibility = Visibility.Collapsed;
            SelectedPath.Visibility = Visibility.Collapsed;
            SelectedMeta.Visibility = Visibility.Collapsed;
            StatusText.Text = "Not Protected";
            StatusPill.Background = (Brush)FindResource("PillLockedBackgroundBrush");
            StatusText.Foreground = (Brush)FindResource("PillLockedTextBrush");
            return;
        }

        var record = _selected.Model;
        var inspection = AclManager.Inspect(record.Path, record);

        NoSelection.Visibility = Visibility.Collapsed;
        ActionsPanel.Visibility = Visibility.Visible;
        SelectedName.Visibility = Visibility.Visible;
        SelectedPath.Visibility = Visibility.Visible;
        SelectedMeta.Visibility = Visibility.Visible;

        SelectedName.Text = record.DisplayName;
        SelectedName.ToolTip = record.DisplayName;
        SelectedPath.Text = record.Path;
        SelectedPath.ToolTip = record.Path;
        SelectedMeta.Text = BuildMetaText(record, inspection);

        StatusText.Text = StatusLabelFor(inspection.State);
        StatusPill.Background = BackgroundFor(inspection.State);
        StatusText.Foreground = ForegroundFor(inspection.State);

        UnlockButton.IsEnabled = inspection.State != ProtectionState.Error;
        LockButton.IsEnabled = inspection.State != ProtectionState.Error;

        if (inspection.State == ProtectionState.Error)
            ShowActionMessage(inspection.Message, isError: true);
    }

    private static string StatusLabelFor(ProtectionState state) => state switch
    {
        ProtectionState.Locked => "Locked",
        ProtectionState.Unlocked => "Unlocked",
        ProtectionState.Error => "Protection Error",
        _ => "Not Protected"
    };

    private Brush BackgroundFor(ProtectionState state) => state switch
    {
        ProtectionState.Unlocked => (Brush)FindResource("PillUnlockedBackgroundBrush"),
        ProtectionState.Error => (Brush)FindResource("PillErrorBackgroundBrush"),
        _ => (Brush)FindResource("PillLockedBackgroundBrush")
    };

    private Brush ForegroundFor(ProtectionState state) => state switch
    {
        ProtectionState.Unlocked => (Brush)FindResource("PillUnlockedTextBrush"),
        ProtectionState.Error => (Brush)FindResource("PillErrorTextBrush"),
        _ => (Brush)FindResource("PillLockedTextBrush")
    };

    private static string BuildMetaText(ProtectedFolder record, AclInspection inspection)
    {
        var text = $"Protected {record.ProtectedUtc:yyyy-MM-dd HH:mm}";

        if (inspection.State == ProtectionState.Unlocked)
            text += " · unlocked for this Windows session";
        else if (inspection.State == ProtectionState.Locked)
            text += " · contents inaccessible";

        if (inspection.NeedsRepair)
            text += " · needs repair";

        if (!string.IsNullOrWhiteSpace(record.LastError))
            text += " · " + record.LastError;

        return text;
    }

    // ---------------------------------------------------------------- actions

    private void Unlock_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is null)
            return;

        var password = FolderPassword.Value;
        if (string.IsNullOrEmpty(password))
        {
            ShowActionMessage("Enter the password for this folder.", isError: true);
            FolderPassword.FocusInput();
            return;
        }

        var result = _protection.Unlock(_selected.Id, password);
        FolderPassword.Clear();

        if (!result.Success)
        {
            SetStatus("Unlock failed — the folder stays locked.");
            RefreshFolderList(_selected.Id);
            ShowActionMessage(result.Message, isError: true);
            FolderPassword.FocusInput();
            return;
        }

        SetStatus(result.Message);
        RefreshFolderList(_selected.Id);
        ShowActionMessage(result.Message, isError: false);
    }

    private void Lock_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is null)
            return;

        var result = _protection.Lock(_selected.Id);
        SetStatus(result.Message);
        RefreshFolderList(_selected.Id);

        if (!result.Success)
            MessageBox.Show(this, result.Message, "FolderGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
    }

    private void ChangePassword_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is null)
            return;

        var dialog = new PasswordDialog { Owner = this };
        dialog.Configure(
            requireNewPassword: true,
            title: "Change password",
            description: $"Enter the current password of '{_selected.Model.DisplayName}' and choose a new one. The folder permissions are not changed.",
            actionLabel: "Change password");

        if (dialog.ShowDialog() != true)
            return;

        var result = _protection.ChangePassword(_selected.Id, dialog.Password, dialog.NewPassword, dialog.NewPassword);
        SetStatus(result.Message);

        if (result.Success)
        {
            RefreshFolderList(_selected.Id);
            MessageBox.Show(this, result.Message, "Password changed", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        else
        {
            MessageBox.Show(this, result.Message, "FolderGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void RemoveProtection_Click(object sender, RoutedEventArgs e)
    {
        if (_selected is null)
            return;

        var dialog = new PasswordDialog { Owner = this };
        dialog.Configure(
            requireNewPassword: false,
            title: "Remove protection",
            description: $"Enter the password of '{_selected.Model.DisplayName}' to restore its original NTFS permissions. No files are deleted or modified.",
            actionLabel: "Remove protection");

        if (dialog.ShowDialog() != true)
            return;

        var result = _protection.RemoveProtection(_selected.Id, dialog.Password);

        if (result.RequiresConfirmation)
        {
            var answer = MessageBox.Show(
                this,
                result.Message,
                "Permissions changed outside FolderGuard",
                MessageBoxButton.OKCancel,
                MessageBoxImage.Warning);

            if (answer != MessageBoxResult.OK)
                return;

            result = _protection.RemoveProtection(_selected.Id, dialog.Password, overwriteExternalChanges: true);
        }

        if (!result.Success)
        {
            ShowActionMessage(result.Message, isError: true);
            MessageBox.Show(this, result.Message, "FolderGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
            RefreshFolderList(_selected.Id);
            return;
        }

        SetStatus(result.Message);
        RefreshFolderList();
        MessageBox.Show(this, result.Message, "Protection removed", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    // ---------------------------------------------------------------- settings actions

    private void OpenDataFolder()
    {
        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"\"{_configuration.DataDirectory}\"",
                UseShellExecute = true
            });
        }
        catch (Exception exception)
        {
            MessageBox.Show(
                this,
                "Could not open the data folder:\n\n" + exception.Message +
                "\n\nIts path is: " + _configuration.DataDirectory,
                "FolderGuard",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private void ReloadConfiguration()
    {
        _configuration.Reload();
        Settings.Initialise(_configuration.DataDirectory);

        if (_configuration.LoadStatus == ConfigurationLoadStatus.Failed)
        {
            ShowBanner(_configuration.LoadError ?? "The configuration store could not be read.");
            Setup.SetEnabledState(false);
            SetStatus("Reload failed — no folder permissions were changed.");
        }
        else
        {
            Banner.Visibility = Visibility.Collapsed;
            Setup.SetEnabledState(true);
            SetStatus("Configuration reloaded.");
        }

        RefreshFolderList();
    }

    private void LockAll()
    {
        if (_configuration.LoadStatus == ConfigurationLoadStatus.Failed)
        {
            SetStatus("Configuration unavailable — nothing was changed.");
            return;
        }

        var failures = 0;
        foreach (var record in _configuration.Configuration.Folders.ToList())
        {
            if (!_protection.ReapplyLock(record.Id).Success)
                failures++;
        }

        RefreshFolderList();
        SetStatus(failures == 0
            ? "All protected folders are locked."
            : $"{failures} folder(s) could not be locked — see the log in the data folder.");
    }

    private void RepairAll()
    {
        if (_configuration.LoadStatus == ConfigurationLoadStatus.Failed)
        {
            SetStatus("Configuration unavailable — nothing was changed.");
            return;
        }

        var repaired = 0;
        var failures = 0;

        foreach (var record in _configuration.Configuration.Folders.ToList())
        {
            var inspection = AclManager.Inspect(record.Path, record);
            if (inspection.State == ProtectionState.Unlocked && inspection.MatchesRecordedState)
                continue;

            if (_protection.ReapplyLock(record.Id).Success)
                repaired++;
            else
                failures++;
        }

        RefreshFolderList();
        SetStatus(
            $"Repair finished: {repaired} folder(s) re-locked, {failures} failure(s).");
    }

    /// <summary>
    /// Re-locks every unlocked folder once the machine has been idle for the configured period.
    /// Windows' own last-input time is used, so activity in any application counts.
    /// </summary>
    private void AutoLockIfIdle()
    {
        if (_configuration.LoadStatus == ConfigurationLoadStatus.Failed)
            return;

        var unlocked = _configuration.Configuration.Folders
            .Where(record => AclManager.Inspect(record.Path, record).State == ProtectionState.Unlocked)
            .ToList();

        if (unlocked.Count == 0)
            return;

        if (IdleMonitor.GetIdleTime() < _autoLockIdleTimeout)
            return;

        var locked = 0;
        var failed = 0;

        foreach (var record in unlocked)
        {
            if (_protection.ReapplyLock(record.Id).Success)
                locked++;
            else
                failed++;
        }

        RefreshFolderList();

        var minutes = _autoLockIdleTimeout.TotalMinutes;
        _logger.Info($"Idle auto-lock: {locked} folder(s) re-locked after {minutes:0} minutes without activity.");

        if (locked > 0)
        {
            ShowBanner($"{locked} folder(s) were locked automatically after {minutes:0} minutes without keyboard or mouse activity.");
            SetStatus("Auto-locked after inactivity.");
        }

        if (failed > 0)
            SetStatus($"{failed} folder(s) could not be auto-locked — see the log in the data folder.");
    }

    // ---------------------------------------------------------------- helpers

    private void RefreshFolderList(string? selectId = null)
    {
        var wanted = selectId
                     ?? _selected?.Id
                     ?? _configuration.Configuration.Settings.LastSelectedFolderId;

        _items.Clear();

        foreach (var record in _configuration.Configuration.Folders)
        {
            var inspection = AclManager.Inspect(record.Path, record);
            var item = new FolderItemViewModel(record);
            item.Update(inspection.State, inspection.Message);
            _items.Add(item);
        }

        CountText.Text = _items.Count switch
        {
            0 => "None",
            1 => "1 folder",
            var count => $"{count} folders"
        };

        EmptyState.Visibility = _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        var target = _items.FirstOrDefault(item => item.Id == wanted) ?? _items.FirstOrDefault();
        FolderList.SelectedItem = target;
        UpdateSelection();

        _lastKnownStates.Clear();
        foreach (var item in _items)
            _lastKnownStates[item.Id] = item.State;
    }

    /// <summary>
    /// Re-reads the protected folders' ACLs while the window is open. If a folder that was
    /// locked suddenly grants the account access (someone edited the permissions by hand),
    /// the status is corrected and the user is warned.
    /// </summary>
    private void CheckForPermissionChanges(bool reportTampering)
    {
        if (_configuration.LoadStatus == ConfigurationLoadStatus.Failed)
            return;

        var changed = false;
        var alerts = new List<string>();

        foreach (var record in _configuration.Configuration.Folders.ToList())
        {
            var inspection = AclManager.Inspect(record.Path, record);
            var previous = _lastKnownStates.TryGetValue(record.Id, out var known) ? known : record.State;

            if (previous != inspection.State)
            {
                changed = true;

                if (reportTampering && inspection.State == ProtectionState.Error && inspection.NeedsRepair &&
                    (previous == ProtectionState.Locked || previous == ProtectionState.Unlocked))
                {
                    alerts.Add(
                        $"'{record.DisplayName}' is no longer enforced: {inspection.Message} " +
                        "Press Repair permissions to lock it again.");
                }
            }

            _lastKnownStates[record.Id] = inspection.State;
        }

        if (changed)
            RefreshFolderList(_selected?.Id);

        if (alerts.Count > 0)
            ShowBanner(string.Join(" ", alerts));
    }

    private void SelectFolder(string id)
    {
        var target = _items.FirstOrDefault(item => item.Id == id);
        if (target is not null)
            FolderList.SelectedItem = target;
    }

    private void ShowActionMessage(string message, bool isError)
    {
        ActionMessage.Text = message;
        ActionMessage.Foreground = isError
            ? (Brush)FindResource("DangerTextBrush")
            : (Brush)FindResource("SuccessTextBrush");
        ActionMessage.Visibility = Visibility.Visible;
    }

    private void SetStatus(string message) => StatusLabel.Text = message;

    private void ShowBanner(string message)
    {
        BannerText.Text = message;
        Banner.Visibility = Visibility.Visible;
    }

    private void DismissBanner_Click(object sender, RoutedEventArgs e)
    {
        Banner.Visibility = Visibility.Collapsed;
    }

}
