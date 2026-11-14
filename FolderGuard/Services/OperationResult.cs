namespace FolderGuard.Services;

/// <summary>Outcome of a protection operation, suitable for direct display.</summary>
public sealed class OperationResult
{
    public bool Success { get; init; }
    public string Message { get; init; } = string.Empty;
    public Models.ProtectionState State { get; init; } = Models.ProtectionState.NotProtected;
    public bool RequiresConfirmation { get; init; }

    public static OperationResult Ok(string message, Models.ProtectionState state) =>
        new() { Success = true, Message = message, State = state };

    public static OperationResult Fail(string message, Models.ProtectionState state = Models.ProtectionState.Error) =>
        new() { Success = false, Message = message, State = state };

    public static OperationResult Confirm(string message) =>
        new() { Success = false, Message = message, RequiresConfirmation = true };
}
