using System.Windows;
using FolderGuard.Services;

namespace FolderGuard.Views;

/// <summary>
/// Confirmation step before protection: shows the exact folder, collects the new password
/// twice and requires an explicit acknowledgement.
/// </summary>
public partial class ProtectFolderDialog : Window
{
    public ProtectFolderDialog(string folderPath)
    {
        InitializeComponent();
        PathText.Text = folderPath;
        Loaded += (_, _) => PasswordInput.FocusInput();
    }

    /// <summary>The confirmed password. Never persisted by this dialog.</summary>
    public string Password { get; private set; } = string.Empty;

    private void Protect_Click(object sender, RoutedEventArgs e)
    {
        if (!PasswordService.IsAcceptable(PasswordInput.Value, out var error))
        {
            ShowError(error);
            return;
        }

        if (!string.Equals(PasswordInput.Value, ConfirmInput.Value, StringComparison.Ordinal))
        {
            ShowError("The two passwords do not match.");
            return;
        }

        if (UnderstandCheck.IsChecked != true)
        {
            ShowError("Tick the confirmation box to continue.");
            return;
        }

        Password = PasswordInput.Value;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        PasswordInput.Clear();
        ConfirmInput.Clear();
        DialogResult = false;
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }
}
