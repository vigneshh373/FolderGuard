using System.ComponentModel;
using System.Windows.Media;
using FolderGuard.Models;

namespace FolderGuard.ViewModels;

/// <summary>List item shown in the dashboard: live status + presentation data.</summary>
public sealed class FolderItemViewModel : INotifyPropertyChanged
{
    private static readonly Brush LockedBackground = Freeze("#EAEAEA");
    private static readonly Brush LockedForeground = Freeze("#3A3A3A");
    private static readonly Brush UnlockedBackground = Freeze("#DFF6DD");
    private static readonly Brush UnlockedForeground = Freeze("#0F5C12");
    private static readonly Brush ErrorBackground = Freeze("#FDE7E9");
    private static readonly Brush ErrorForeground = Freeze("#9C1B14");
    private static readonly Brush IdleBackground = Freeze("#EAEAEA");
    private static readonly Brush IdleForeground = Freeze("#3A3A3A");

    private ProtectionState _state;
    private string _detail = string.Empty;

    public FolderItemViewModel(ProtectedFolder model)
    {
        Model = model;
        _state = model.State;
    }

    public ProtectedFolder Model { get; }

    public string Id => Model.Id;

    public string Name => Model.DisplayName;

    public string PathText => Model.Path;

    public ProtectionState State => _state;

    public string StatusText => _state switch
    {
        ProtectionState.Locked => "Locked",
        ProtectionState.Unlocked => "Unlocked",
        ProtectionState.Error => "Protection Error",
        _ => "Not Protected"
    };

    public Brush StatusBackground => _state switch
    {
        ProtectionState.Unlocked => UnlockedBackground,
        ProtectionState.Error => ErrorBackground,
        ProtectionState.Locked => LockedBackground,
        _ => IdleBackground
    };

    public Brush StatusForeground => _state switch
    {
        ProtectionState.Unlocked => UnlockedForeground,
        ProtectionState.Error => ErrorForeground,
        ProtectionState.Locked => LockedForeground,
        _ => IdleForeground
    };

    public string Detail => _detail;

    public void Update(ProtectionState state, string detail)
    {
        _state = state;
        _detail = detail;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(string.Empty));
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private static Brush Freeze(string hex)
    {
        var brush = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        brush.Freeze();
        return brush;
    }
}
