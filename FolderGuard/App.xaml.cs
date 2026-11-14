using System.IO;
using System.Windows;
using System.Windows.Threading;
using FolderGuard.Services;

namespace FolderGuard;

public partial class App : Application
{
    /// <summary>Set when the restore/backup privileges could not be enabled; shown as a banner.</summary>
    internal static string? PrivilegeWarning { get; private set; }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);

        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += (_, args) =>
        {
            if (args.ExceptionObject is Exception exception)
                TryLog("Unhandled background exception", exception);
        };

        if (!AclManager.IsElevated())
        {
            MessageBox.Show(
                "FolderGuard needs administrator rights to change NTFS folder permissions.\n\n" +
                "Close FolderGuard and start it again, and approve the Windows elevation prompt.",
                "FolderGuard",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            Shutdown(1);
            return;
        }

        if (!TokenPrivileges.Enable(out var privilegeFailure))
        {
            PrivilegeWarning =
                "FolderGuard could not enable the restore/backup privileges it needs to rewrite protected " +
                "permissions safely (" + privilegeFailure + "). Locking and unlocking may fail on this machine.";
            TryLog(PrivilegeWarning, new InvalidOperationException(privilegeFailure));
        }

        var window = new MainWindow();
        MainWindow = window;
        window.Show();
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        TryLog("Unhandled user-interface exception", e.Exception);
        MessageBox.Show(
            "FolderGuard hit an unexpected error:\n\n" + e.Exception.Message +
            "\n\nThe folder permissions were not changed by this error. Details were written to the FolderGuard log " +
            "(Settings → Open data folder).",
            "FolderGuard",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
        e.Handled = true;
    }

    private static void TryLog(string message, Exception exception)
    {
        try
        {
            var options = AppOptions.Load();
            var directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                options.DataDirectoryName,
                "logs");
            new Logger(directory).Error(message, exception);
        }
        catch
        {
            // Never fail while reporting a failure.
        }
    }
}
