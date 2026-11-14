namespace FolderGuard.Models;

/// <summary>
/// Persisted state of one protected folder.
/// </summary>
public enum ProtectionState
{
    /// <summary>The folder is not tracked by FolderGuard.</summary>
    NotProtected = 0,

    /// <summary>Contents are inaccessible to the interactive user (default persistent state).</summary>
    Locked = 1,

    /// <summary>Contents are accessible to the current interactive Windows session only.</summary>
    Unlocked = 2,

    /// <summary>FolderGuard could not read or apply the permissions for this folder.</summary>
    Error = 3
}

/// <summary>
/// Everything FolderGuard stores about a single protected folder.
/// Passwords are never stored: only a PBKDF2 salt and verification hash are kept.
/// </summary>
public sealed class ProtectedFolder
{
    /// <summary>Stable identifier used by the configuration and the journal.</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    /// <summary>Absolute path of the protected folder.</summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>When protection was first applied.</summary>
    public DateTimeOffset ProtectedUtc { get; set; } = DateTimeOffset.Now;

    /// <summary>When the record last changed (password, lock state, repair).</summary>
    public DateTimeOffset LastChangedUtc { get; set; } = DateTimeOffset.Now;

    /// <summary>Last known protection state. The live state is always re-read from the ACL.</summary>
    public ProtectionState State { get; set; } = ProtectionState.Locked;

    /// <summary>Base64 PBKDF2 salt (16 random bytes, unique per folder).</summary>
    public string PasswordSalt { get; set; } = string.Empty;

    /// <summary>Base64 PBKDF2-SHA256 verification hash (32 bytes).</summary>
    public string PasswordHash { get; set; } = string.Empty;

    /// <summary>Iteration count actually used for <see cref="PasswordHash"/>.</summary>
    public int PasswordIterations { get; set; } = 600_000;

    /// <summary>DACL of the folder before protection was applied, in SDDL form.</summary>
    public string OriginalDaclSddl { get; set; } = string.Empty;

    /// <summary>Owner SID at the time protection was applied (informational).</summary>
    public string OriginalOwnerSid { get; set; } = string.Empty;

    /// <summary>Primary group SID at the time protection was applied (informational).</summary>
    public string OriginalGroupSid { get; set; } = string.Empty;

    /// <summary>Fingerprint of the locked DACL that FolderGuard applied.</summary>
    public string LockedDaclHash { get; set; } = string.Empty;

    /// <summary>Fingerprint of the unlocked DACL that FolderGuard applied (session bound).</summary>
    public string UnlockedDaclHash { get; set; } = string.Empty;

    /// <summary>Logon session SID used for the current unlock, if any (S-1-5-5-x-y).</summary>
    public string? UnlockLogonSid { get; set; }

    /// <summary>When the folder was last unlocked, if any.</summary>
    public DateTimeOffset? UnlockedUtc { get; set; }

    /// <summary>Last error message, if the record is in <see cref="ProtectionState.Error"/>.</summary>
    public string? LastError { get; set; }

    public string DisplayName
    {
        get
        {
            try
            {
                var name = System.IO.Path.GetFileName(Path.TrimEnd('\\', '/'));
                return string.IsNullOrEmpty(name) ? Path : name;
            }
            catch
            {
                return Path;
            }
        }
    }
}
