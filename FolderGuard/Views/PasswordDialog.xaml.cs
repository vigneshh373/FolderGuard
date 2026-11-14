using System.Windows;
using FolderGuard.Services;

namespace FolderGuard.Views;

/// <summary>
/// Used for "Change password" (current + new + confirmation) and for verifying the password
/// before a destructive action such as removing protection.
/// </summary>
public partial class PasswordDialog : Window
{
    private bool _requireNewPassword;

    public PasswordDialog()
    {
        InitializeComponent();
    }

    public string Password { get; private set; } = string.Empty;

    public string NewPassword { get; private set; } = string.Empty;

    public void Configure(bool requireNewPassword, string title, string description, string actionLabel)
    {
        _requireNewPassword = requireNewPassword;
        Title = title;
        TitleBlock.Text = title;
        DescriptionBlock.Text = description;
        ConfirmButton.Content = actionLabel;
        CurrentLabel.Text = requireNewPassword ? "Current password" : "Password";
        NewPasswordPanel.Visibility = requireNewPassword ? Visibility.Visible : Visibility.Collapsed;

        Loaded += (_, _) => CurrentInput.FocusInput();
    }

    private void Confirm_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(CurrentInput.Value))
        {
            ShowError("Enter the password.");
            return;
        }

        if (_requireNewPassword)
        {
            if (!PasswordService.IsAcceptable(NewInput.Value, out var error))
            {
                ShowError(error);
                return;
            }

            if (!string.Equals(NewInput.Value, ConfirmInput.Value, StringComparison.Ordinal))
            {
                ShowError("The two new passwords do not match.");
                return;
            }

            if (string.Equals(NewInput.Value, CurrentInput.Value, StringComparison.Ordinal))
            {
                ShowError("The new password must be different from the current one.");
                return;
            }

            NewPassword = NewInput.Value;
        }

        Password = CurrentInput.Value;
        DialogResult = true;
    }

    private void Cancel_Click(object sender, RoutedEventArgs e)
    {
        CurrentInput.Clear();
        NewInput.Clear();
        ConfirmInput.Clear();
        DialogResult = false;
    }

    private void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }
}
