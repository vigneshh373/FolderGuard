namespace FolderGuard.Models;

/// <summary>
/// Root of the DPAPI-protected configuration document.
/// </summary>
public sealed class FolderConfiguration
{
    public int SchemaVersion { get; set; } = 1;

    public List<ProtectedFolder> Folders { get; set; } = new();

    public AppSettings Settings { get; set; } = new();
}

/// <summary>
/// Application-wide options stored next to the folder records.
/// </summary>
public sealed class AppSettings
{
    /// <summary>PBKDF2 iterations used for folders created with this installation.</summary>
    public int Pbkdf2Iterations { get; set; } = 600_000;

    /// <summary>Id of the folder that was selected last, for convenience.</summary>
    public string? LastSelectedFolderId { get; set; }
}
