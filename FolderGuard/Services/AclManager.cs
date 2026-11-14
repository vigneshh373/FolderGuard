using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using FolderGuard.Models;

namespace FolderGuard.Services;

/// <summary>Captured permissions of a folder, in a form that can be written back verbatim.</summary>
public sealed record AclSnapshot(string DaclSddl, string OwnerSid, string GroupSid);

/// <summary>Result of comparing a folder's live ACL with its FolderGuard record.</summary>
public sealed class AclInspection
{
    public ProtectionState State { get; init; } = ProtectionState.Error;
    public string Message { get; init; } = string.Empty;
    public bool MatchesRecordedState { get; init; }
    public bool NeedsRepair { get; init; }
    public string CurrentDaclHash { get; init; } = string.Empty;
    public bool SessionUnlocked { get; init; }
}

/// <summary>
/// All NTFS security-descriptor work lives here.
///
/// Locked DACL (the persistent default state):
///   * inheritance disabled, inherited ACEs discarded
///   * NT AUTHORITY\SYSTEM            : FullControl (folders + descendants)
///   * BUILTIN\Administrators         : FullControl (folders + descendants)
///   * OWNER RIGHTS (S-1-3-4)         : ReadPermissions only
/// No ACE mentions the interactive user's SID, so Explorer cannot open the contents.
///
/// Unlocked DACL (session bound):
///   * identical, plus one FullControl ACE for the *logon session SID* (S-1-5-5-x-y).
/// The logon SID only exists in tokens of the current interactive logon session, so the
/// grant dies with the session / reboot without anything having to run at shutdown.
/// </summary>
public static class AclManager
{
    private static readonly SecurityIdentifier SystemSid = new(WellKnownSidType.LocalSystemSid, null);
    private static readonly SecurityIdentifier AdministratorsSid = new(WellKnownSidType.BuiltinAdministratorsSid, null);

    /// <summary>
    /// OWNER RIGHTS. An explicit ACE for this SID suppresses the implicit READ_CONTROL and
    /// WRITE_DAC that a folder owner would otherwise receive, so the owner cannot simply
    /// re-grant themselves access from Explorer's security dialog.
    /// </summary>
    public static readonly SecurityIdentifier OwnerRightsSid = new("S-1-3-4");

    private const InheritanceFlags Inherit = InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit;

    private const AccessControlSections CaptureSections =
        AccessControlSections.Access | AccessControlSections.Owner | AccessControlSections.Group;

    public const FileSystemRights DataRights =
        FileSystemRights.ReadData |
        FileSystemRights.WriteData |
        FileSystemRights.AppendData |
        FileSystemRights.ReadExtendedAttributes |
        FileSystemRights.WriteExtendedAttributes |
        FileSystemRights.ExecuteFile |
        FileSystemRights.Delete |
        FileSystemRights.DeleteSubdirectoriesAndFiles |
        FileSystemRights.ReadAttributes |
        FileSystemRights.WriteAttributes;

    public static SecurityIdentifier CurrentUserSid =>
        WindowsIdentity.GetCurrent().User ?? new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);

    /// <summary>Diagnostic text describing how the last logon-session lookup went.</summary>
    public static string LastLogonSidDiagnostics { get; private set; } = string.Empty;

    /// <summary>
    /// Returns the logon-session SID (S-1-5-5-x-y) of the current interactive session, or null
    /// when the token has none (for example a non-interactive service context).
    /// </summary>
    public static SecurityIdentifier? GetCurrentLogonSid()
    {
        var sid = LogonSessionSid.Get(out var diagnostics);
        LastLogonSidDiagnostics = diagnostics;
        return sid;
    }

    public static bool IsLogonSessionSid(SecurityIdentifier sid) => LogonSessionSid.IsLogonSessionSid(sid);

    public static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    // ---------------------------------------------------------------- capture / restore

    public static DirectorySecurity GetSecurity(string path) =>
        new DirectoryInfo(path).GetAccessControl(CaptureSections);

    public static AclSnapshot Capture(string path)
    {
        var security = GetSecurity(path);
        var owner = (security.GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value ?? string.Empty;
        var group = (security.GetGroup(typeof(SecurityIdentifier)) as SecurityIdentifier)?.Value ?? string.Empty;
        var dacl = security.GetSecurityDescriptorSddlForm(AccessControlSections.Access);
        return new AclSnapshot(dacl, owner, group);
    }

    /// <summary>
    /// Writes back a previously captured DACL. Only the ACL section is applied, so the owner,
    /// the group and any other security-descriptor data are left untouched.
    /// </summary>
    public static void Restore(string path, AclSnapshot snapshot)
    {
        if (string.IsNullOrWhiteSpace(snapshot.DaclSddl))
            throw new InvalidOperationException("No permission backup is available for this folder.");

        var security = new DirectorySecurity();
        security.SetSecurityDescriptorSddlForm(snapshot.DaclSddl, AccessControlSections.Access);
        new DirectoryInfo(path).SetAccessControl(security);
    }

    // ---------------------------------------------------------------- locked / unlocked DACLs

    public static DirectorySecurity BuildLockedSecurity()
    {
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        security.AddAccessRule(new FileSystemAccessRule(
            SystemSid, FileSystemRights.FullControl, Inherit, PropagationFlags.None, AccessControlType.Allow));

        // Administrators may only READ the security descriptor: no data rights and no WRITE_DAC.
        // Granting either would let Explorer's "Continue to permanently get access" elevation
        // prompt re-grant access with a single click. Recovery is still possible because
        // FolderGuard enables SeRestorePrivilege/SeBackupPrivilege in its own elevated token,
        // and an administrator can deliberately take ownership (takeown) when needed.
        security.AddAccessRule(new FileSystemAccessRule(
            AdministratorsSid, FileSystemRights.ReadPermissions, Inherit, PropagationFlags.None, AccessControlType.Allow));

        // Suppress the owner's implicit READ_CONTROL/WRITE_DAC: the owner keeps read-permissions
        // so the folder is still inspectable, but cannot rewrite the DACL from Explorer.
        security.AddAccessRule(new FileSystemAccessRule(
            OwnerRightsSid, FileSystemRights.ReadPermissions, InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));

        return security;
    }

    public static DirectorySecurity BuildUnlockedSecurity(SecurityIdentifier logonSid)
    {
        var security = BuildLockedSecurity();
        security.AddAccessRule(new FileSystemAccessRule(
            logonSid, FileSystemRights.FullControl, Inherit, PropagationFlags.None, AccessControlType.Allow));
        return security;
    }

    /// <summary>Applies a DACL, reads it back and verifies it matches what was requested.</summary>
    public static string ApplySecurity(string path, DirectorySecurity intended, bool expectInheritanceProtected)
    {
        var expectedHash = ComputeDaclHash(intended);
        new DirectoryInfo(path).SetAccessControl(intended);

        var applied = GetSecurity(path);
        if (applied.AreAccessRulesProtected != expectInheritanceProtected)
        {
            throw new IOException(
                "The folder did not accept the new permission set (inheritance state mismatch). " +
                "The folder may be a reparse point or the security descriptor may be managed by policy.");
        }

        var actualHash = ComputeDaclHash(applied);
        if (!string.Equals(expectedHash, actualHash, StringComparison.Ordinal))
        {
            throw new IOException(
                "The folder did not accept the new permission set (access rules were altered after they were written). " +
                "No further permission changes will be made.");
        }

        return actualHash;
    }

    /// <summary>
    /// Stable fingerprint of a DACL: canonical, order-independent, includes the inheritance flag.
    /// Two security descriptors with the same access rules always produce the same hash.
    /// </summary>
    public static string ComputeDaclHash(FileSystemSecurity security)
    {
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Select(rule => string.Join("|",
                rule.AccessControlType,
                rule.IdentityReference.Value,
                ((int)rule.FileSystemRights).ToString(),
                rule.InheritanceFlags,
                rule.PropagationFlags))
            .OrderBy(text => text, StringComparer.Ordinal);

        var payload = (security.AreAccessRulesProtected ? "P1" : "P0") + ";" + string.Join(";", rules);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(payload)));
    }

    // ---------------------------------------------------------------- inspection

    /// <summary>
    /// Derives the live protection state from the folder's ACL. The persisted state is never
    /// trusted on its own: after a reboot the ACL still contains the old session ACE, but no
    /// token carries that SID any more, which is exactly why the folder is locked again.
    /// </summary>
    public static AclInspection Inspect(string path, ProtectedFolder record)
    {
        try
        {
            if (!Directory.Exists(path))
            {
                return new AclInspection
                {
                    State = ProtectionState.Error,
                    Message = "The folder no longer exists at this path.",
                    CurrentDaclHash = string.Empty
                };
            }

            var security = GetSecurity(path);
            var hash = ComputeDaclHash(security);
            var rules = security.GetAccessRules(true, false, typeof(SecurityIdentifier))
                .Cast<FileSystemAccessRule>()
                .ToList();

            var logonSid = GetCurrentLogonSid();
            var userSid = CurrentUserSid;

            var sessionGrant = logonSid is not null && rules.Any(rule =>
                rule.AccessControlType == AccessControlType.Allow &&
                rule.IdentityReference.Equals(logonSid) &&
                (rule.FileSystemRights & FileSystemRights.ReadData) == FileSystemRights.ReadData);

            var userGrant = rules.Any(rule =>
                rule.AccessControlType == AccessControlType.Allow &&
                rule.IdentityReference.Equals(userSid) &&
                (rule.FileSystemRights & (FileSystemRights.ReadData | FileSystemRights.ListDirectory)) != 0);

            var staleSessionGrant = rules.Any(rule =>
                rule.AccessControlType == AccessControlType.Allow &&
                rule.IdentityReference is SecurityIdentifier ruleSid &&
                IsLogonSessionSid(ruleSid) &&
                (logonSid is null || !rule.IdentityReference.Equals(logonSid)));

            var matchesLocked = !string.IsNullOrEmpty(record.LockedDaclHash) &&
                                string.Equals(hash, record.LockedDaclHash, StringComparison.OrdinalIgnoreCase);

            // Older FolderGuard builds granted Administrators full control in the locked DACL,
            // which let Explorer's "Continue" elevation button re-open the folder. Treat such a
            // DACL as needing an upgrade so start-up recovery re-applies the hardened set.
            var administratorsOverPrivileged = rules.Any(rule =>
                rule.AccessControlType == AccessControlType.Allow &&
                rule.IdentityReference.Equals(AdministratorsSid) &&
                (rule.FileSystemRights &
                 (DataRights | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership)) != 0);

            if (sessionGrant)
            {
                return new AclInspection
                {
                    State = ProtectionState.Unlocked,
                    Message = "Unlocked for this Windows session.",
                    MatchesRecordedState = true,
                    CurrentDaclHash = hash,
                    SessionUnlocked = true
                };
            }

            if (staleSessionGrant)
            {
                return new AclInspection
                {
                    State = ProtectionState.Locked,
                    Message = "Contents are locked. A leftover permission from a previous Windows session can be cleaned up.",
                    MatchesRecordedState = false,
                    NeedsRepair = true,
                    CurrentDaclHash = hash
                };
            }

            if (matchesLocked && !userGrant)
            {
                return new AclInspection
                {
                    State = ProtectionState.Locked,
                    Message = administratorsOverPrivileged
                        ? "Contents are locked, but the permission set is out of date and should be upgraded (Repair permissions)."
                        : "Contents are locked.",
                    MatchesRecordedState = !administratorsOverPrivileged,
                    NeedsRepair = administratorsOverPrivileged,
                    CurrentDaclHash = hash
                };
            }

            if (!userGrant)
            {
                return new AclInspection
                {
                    State = ProtectionState.Locked,
                    Message = "Contents are locked (the permissions differ from the recorded snapshot).",
                    MatchesRecordedState = false,
                    NeedsRepair = true,
                    CurrentDaclHash = hash
                };
            }

            return new AclInspection
            {
                State = ProtectionState.Error,
                Message = "Protection was altered outside FolderGuard: your account currently has direct access to the contents.",
                MatchesRecordedState = false,
                NeedsRepair = true,
                CurrentDaclHash = hash
            };
        }
        catch (Exception exception)
        {
            return new AclInspection
            {
                State = ProtectionState.Error,
                Message = "Could not read the folder permissions: " + exception.Message,
                CurrentDaclHash = string.Empty
            };
        }
    }

    // ---------------------------------------------------------------- path validation

    /// <summary>
    /// Rejects paths that FolderGuard must never touch (drive roots, system directories, the
    /// application's own directory, reparse points, non-NTFS volumes, ...).
    /// </summary>
    public static bool ValidateFolder(string? candidate, out string normalizedPath, out string error)
    {
        normalizedPath = string.Empty;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(candidate))
        {
            error = "Choose a folder first.";
            return false;
        }

        string full;
        try
        {
            full = Path.GetFullPath(candidate.Trim().TrimEnd('\\', '/'));
        }
        catch (Exception exception)
        {
            error = "That path is not valid: " + exception.Message;
            return false;
        }

        if (!Directory.Exists(full))
        {
            error = "That folder does not exist.";
            return false;
        }

        var root = Path.GetPathRoot(full) ?? string.Empty;
        if (string.Equals(full.TrimEnd('\\'), root.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
        {
            error = "A whole drive cannot be protected. Choose a folder inside the drive.";
            return false;
        }

        try
        {
            var attributes = File.GetAttributes(full);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
            {
                error = "That folder is a reparse point (junction or symbolic link). Choose a physical folder.";
                return false;
            }
        }
        catch (Exception exception)
        {
            error = "That folder cannot be inspected: " + exception.Message;
            return false;
        }

        string format;
        try
        {
            format = new DriveInfo(root).DriveFormat;
        }
        catch (Exception exception)
        {
            error = "The drive of that folder cannot be inspected: " + exception.Message;
            return false;
        }

        if (!format.Equals("NTFS", StringComparison.OrdinalIgnoreCase) &&
            !format.Equals("ReFS", StringComparison.OrdinalIgnoreCase))
        {
            error = $"That drive uses the {format} file system. FolderGuard needs NTFS or ReFS ACLs.";
            return false;
        }

        var systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        if (!string.IsNullOrEmpty(systemRoot) && IsSameOrInside(full, systemRoot))
        {
            error = "The Windows directory and its contents cannot be protected.";
            return false;
        }

        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        if ((!string.IsNullOrEmpty(programFiles) && IsSameOrInside(full, programFiles)) ||
            (!string.IsNullOrEmpty(programFilesX86) && IsSameOrInside(full, programFilesX86)))
        {
            error = "Program Files directories cannot be protected.";
            return false;
        }

        var applicationDirectory = AppContext.BaseDirectory.TrimEnd('\\');
        if (!string.IsNullOrEmpty(applicationDirectory) &&
            (IsSameOrInside(full, applicationDirectory) || IsSameOrInside(applicationDirectory, full)))
        {
            error = "FolderGuard's own directory (or a parent of it) cannot be protected.";
            return false;
        }

        var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        if (!string.IsNullOrEmpty(userProfile) &&
            string.Equals(full.TrimEnd('\\'), userProfile.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
        {
            error = "Your user profile root cannot be protected. Choose a folder inside it.";
            return false;
        }

        normalizedPath = full;
        return true;
    }

    /// <summary>True when <paramref name="path"/> equals <paramref name="parent"/> or is below it.</summary>
    public static bool IsSameOrInside(string path, string parent)
    {
        if (string.IsNullOrEmpty(path) || string.IsNullOrEmpty(parent))
            return false;

        var normalizedPath = path.TrimEnd('\\', '/');
        var normalizedParent = parent.TrimEnd('\\', '/');

        if (string.Equals(normalizedPath, normalizedParent, StringComparison.OrdinalIgnoreCase))
            return true;

        return normalizedPath.StartsWith(normalizedParent + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);
    }
}
