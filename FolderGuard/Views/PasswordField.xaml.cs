using System.Windows;
using System.Windows.Controls;

namespace FolderGuard.Views;

/// <summary>Password entry with a show/hide toggle, used by the dashboard and the dialogs.</summary>
public partial class PasswordField : UserControl
{
    private bool _syncing;

    public PasswordField()
    {
        InitializeComponent();
    }

    /// <summary>The current password text, regardless of which control is visible.</summary>
    public string Value
    {
        get => ShownBox.Visibility == Visibility.Visible ? ShownBox.Text : HiddenBox.Password;
        set
        {
            _syncing = true;
            HiddenBox.Password = value ?? string.Empty;
            ShownBox.Text = value ?? string.Empty;
            _syncing = false;
        }
    }

    public void Clear()
    {
        Value = string.Empty;
        ShowPlainText(false);
    }

    public void FocusInput()
    {
        if (ShownBox.Visibility == Visibility.Visible)
            ShownBox.Focus();
        else
            HiddenBox.Focus();
    }

    private void ToggleButton_Click(object sender, RoutedEventArgs e)
    {
        ShowPlainText(ShownBox.Visibility != Visibility.Visible);
    }

    private void ShowPlainText(bool plain)
    {
        _syncing = true;
        if (plain)
        {
            ShownBox.Text = HiddenBox.Password;
            ShownBox.Visibility = Visibility.Visible;
            HiddenBox.Visibility = Visibility.Collapsed;
            ToggleButton.Content = "Hide";
            ShownBox.CaretIndex = ShownBox.Text.Length;
            ShownBox.Focus();
        }
        else
        {
            HiddenBox.Password = ShownBox.Text;
            HiddenBox.Visibility = Visibility.Visible;
            ShownBox.Visibility = Visibility.Collapsed;
            ToggleButton.Content = "Show";
            HiddenBox.Focus();
        }

        _syncing = false;
    }

    private void HiddenBox_PasswordChanged(object sender, RoutedEventArgs e)
    {
        if (_syncing)
            return;

        _syncing = true;
        ShownBox.Text = HiddenBox.Password;
        _syncing = false;
    }

    private void ShownBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        if (_syncing)
            return;

        _syncing = true;
        HiddenBox.Password = ShownBox.Text;
        _syncing = false;
    }
}
