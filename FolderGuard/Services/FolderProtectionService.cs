using System.IO;
using System.Security.Principal;
using FolderGuard.Models;

namespace FolderGuard.Services;

/// <summary>
/// Orchestrates protect / unlock / lock / password change / removal.
///
/// Safety rules used throughout:
///  * every mutation is journalled first and the entry is cleared only after verification,
///  * a failed mutation rolls the folder's ACL back to the captured snapshot,
///  * nothing outside the selected folder's own security descriptor is written
///    (descendants receive access solely through ACL inheritance),
///  * no operation ever deletes, moves, encrypts or modifies folder contents.
/// </summary>
public sealed class FolderProtectionService
{
    private readonly ConfigurationService _configuration;
    private readonly JournalStore _journal;
    private readonly Logger _logger;

    public FolderProtectionService(ConfigurationService configuration, JournalStore journal, Logger logger)
    {
        _configuration = configuration;
        _journal = journal;
        _logger = logger;
    }

    // ---------------------------------------------------------------- protect

    public OperationResult Protect(string folderPath, string password, string confirmation)
    {
        if (_configuration.LoadStatus == ConfigurationLoadStatus.Failed)
            return OperationResult.Fail("The configuration store is unreadable, so protection cannot be applied safely. See Settings → Open data folder.");

        if (!AclManager.ValidateFolder(folderPath, out var path, out var pathError))
            return OperationResult.Fail(pathError);

        var existing = _configuration.FindByPath(path);
        if (existing is not null)
        {
            return OperationResult.Fail(
                $"'{path}' is already protected with FolderGuard (status: {existing.State}).",
                ProtectionState.NotProtected);
        }

        var nested = _configuration.Configuration.Folders.FirstOrDefault(folder =>
            AclManager.IsSameOrInside(path, folder.Path) || AclManager.IsSameOrInside(folder.Path, path));
        if (nested is not null)
        {
            return OperationResult.Fail(
                $"'{path}' overlaps the protected folder '{nested.Path}'. Nested protection is not supported; " +
                "choose a folder that does not contain, and is not inside, another protected folder.");
        }

        if (!PasswordService.IsAcceptable(password, out var passwordError))
            return OperationResult.Fail(passwordError, ProtectionState.NotProtected);

        if (!string.Equals(password, confirmation, StringComparison.Ordinal))
            return OperationResult.Fail("The two passwords do not match.", ProtectionState.NotProtected);

        AclSnapshot snapshot;
        try
        {
            snapshot = AclManager.Capture(path);
        }
        catch (Exception exception)
        {
            _logger.Error($"Could not capture permissions for '{path}'", exception);
            return OperationResult.Fail(
                "FolderGuard could not read the current permissions of this folder, so nothing was changed. " +
                $"Details: {exception.Message}");
        }

        var material = PasswordService.Create(password, _configuration.Configuration.Settings.Pbkdf2Iterations);
        var record = new ProtectedFolder
        {
            Path = path,
            ProtectedUtc = DateTimeOffset.Now,
            LastChangedUtc = DateTimeOffset.Now,
            State = ProtectionState.Locked,
            PasswordSalt = material.SaltBase64,
            PasswordHash = material.HashBase64,
            PasswordIterations = material.Iterations,
            OriginalDaclSddl = snapshot.DaclSddl,
            OriginalOwnerSid = snapshot.OwnerSid,
            OriginalGroupSid = snapshot.GroupSid
        };

        _journal.Write(new JournalEntry
        {
            FolderId = record.Id,
            FolderPath = path,
            Operation = JournalOperation.Protect,
            OriginalDaclSddl = snapshot.DaclSddl,
            TargetDescription = "locked"
        });

        try
        {
            var hash = AclManager.ApplySecurity(path, AclManager.BuildLockedSecurity(), expectInheritanceProtected: true);
            record.LockedDaclHash = hash;
            record.State = ProtectionState.Locked;

            _configuration.Configuration.Folders.Add(record);
            _configuration.Configuration.Settings.LastSelectedFolderId = record.Id;

            if (!_configuration.Save())
            {
                throw new InvalidOperationException(
                    "The protected permissions were applied but the configuration could not be saved, so the operation was rolled back.");
            }

            _journal.Clear(record.Id);
            _logger.Info($"Protected '{path}'.");
            return OperationResult.Ok(
                $"'{record.DisplayName}' is now protected. Its contents are locked until you unlock it with its password.",
                ProtectionState.Locked);
        }
        catch (Exception exception)
        {
            _logger.Error($"Protection failed for '{path}'; rolling back.", exception);

            string rollbackNote;
            try
            {
                AclManager.Restore(path, snapshot);
                _configuration.Configuration.Folders.Remove(record);
                _configuration.Save();
                _journal.Clear(record.Id);
                rollbackNote = "The original permissions were restored.";
            }
            catch (Exception rollbackException)
            {
                _logger.Error($"Rollback failed for '{path}'.", rollbackException);
                record.State = ProtectionState.Error;
                record.LastError = rollbackException.Message;
                record.OriginalDaclSddl = snapshot.DaclSddl;
                _configuration.Configuration.Folders.Remove(record);
                _configuration.Configuration.Folders.Add(record);
                _configuration.Save();
                rollbackNote =
                    "The original permissions could NOT be restored automatically. The folder is listed with a " +
                    "Protection Error status: use 'Repair permissions' or 'Remove protection' to recover it.";
            }

            return OperationResult.Fail($"Protection failed: {exception.Message} {rollbackNote}");
        }
    }

    // ---------------------------------------------------------------- unlock

    public OperationResult Unlock(string folderId, string password)
    {
        var record = _configuration.FindById(folderId);
        if (record is null)
            return OperationResult.Fail("That folder is no longer in the FolderGuard list.", ProtectionState.NotProtected);

        if (!Directory.Exists(record.Path))
        {
            record.State = ProtectionState.Error;
            record.LastError = "Folder not found.";
            _configuration.Save();
            return OperationResult.Fail("The folder no longer exists at its recorded path.", ProtectionState.Error);
        }

        if (!PasswordService.Verify(password, record.PasswordSalt, record.PasswordHash, record.PasswordIterations))
        {
            _logger.Warn($"Rejected an unlock attempt for '{record.Path}' (wrong password).");
            return OperationResult.Fail("Incorrect password. The folder stays locked.", ProtectionState.Locked);
        }

        var logonSid = AclManager.GetCurrentLogonSid();
        if (logonSid is null)
        {
            _logger.Error(
                "Could not determine the logon session SID, so the unlock was refused. Diagnostics: " +
                AclManager.LastLogonSidDiagnostics, null);

            return OperationResult.Fail(
                "FolderGuard could not determine the logon session of this Windows session, so the folder was not unlocked. " +
                "Diagnostics: " + AclManager.LastLogonSidDiagnostics + " — details were written to the FolderGuard log.",
                record.State);
        }

        AclSnapshot? snapshot = string.IsNullOrWhiteSpace(record.OriginalDaclSddl)
            ? null
            : new AclSnapshot(record.OriginalDaclSddl, record.OriginalOwnerSid, record.OriginalGroupSid);

        _journal.Write(new JournalEntry
        {
            FolderId = record.Id,
            FolderPath = record.Path,
            Operation = JournalOperation.Unlock,
            OriginalDaclSddl = record.OriginalDaclSddl,
            TargetDescription = "unlocked for " + logonSid.Value
        });

        try
        {
            var hash = AclManager.ApplySecurity(record.Path, AclManager.BuildUnlockedSecurity(logonSid), expectInheritanceProtected: true);
            record.UnlockedDaclHash = hash;
            record.UnlockLogonSid = logonSid.Value;
            record.UnlockedUtc = DateTimeOffset.Now;
            record.State = ProtectionState.Unlocked;
            record.LastError = null;
            record.LastChangedUtc = DateTimeOffset.Now;
            _configuration.Save();
            _journal.Clear(record.Id);

            _logger.Info($"Unlocked '{record.Path}' for the current Windows session.");
            return OperationResult.Ok(
                "'{0}' is unlocked for this Windows session. It locks again when you press Lock, when you sign out, or when Windows restarts.".Replace("{0}", record.DisplayName),
                ProtectionState.Unlocked);
        }
        catch (Exception exception)
        {
            _logger.Error($"Unlock failed for '{record.Path}'.", exception);

            // Fail closed: try to put the folder back into the locked state first, never leave it open.
            try
            {
                var lockedHash = AclManager.ApplySecurity(record.Path, AclManager.BuildLockedSecurity(), expectInheritanceProtected: true);
                record.LockedDaclHash = lockedHash;
                record.State = ProtectionState.Locked;
                record.UnlockLogonSid = null;
                record.LastError = null;
                _configuration.Save();
                _journal.Clear(record.Id);
                return OperationResult.Fail(
                    $"The folder could not be unlocked ({exception.Message}). It was re-locked and stays protected.");
            }
            catch (Exception lockException)
            {
                _logger.Error($"Could not re-lock '{record.Path}' after a failed unlock.", lockException);
            }

            // Last resort: restore the pre-protection permissions so the user cannot be locked out of
            // their own data. The record is then flagged as an error because the folder is not protected.
            if (snapshot is not null)
            {
                try
                {
                    AclManager.Restore(record.Path, snapshot);
                    record.State = ProtectionState.Error;
                    record.LastError =
                        "Unlock failed and the folder could not be re-locked. The original permissions were restored, " +
                        "so the folder is currently NOT protected. Use Repair permissions or Remove Protection.";
                    _configuration.Save();
                    _journal.Clear(record.Id);
                    return OperationResult.Fail(
                        $"The folder could not be unlocked or re-locked ({exception.Message}). Its original permissions were restored, " +
                        "so it is currently NOT protected — the entry is marked as Protection Error.");
                }
                catch (Exception rollbackException)
                {
                    _logger.Error($"Could not restore the original permissions for '{record.Path}'.", rollbackException);
                }
            }

            record.State = ProtectionState.Error;
            record.LastError = exception.Message;
            _configuration.Save();
            return OperationResult.Fail(
                $"The folder could not be unlocked and its permissions are in an unknown state. Error: {exception.Message}");
        }
    }

    // ---------------------------------------------------------------- lock

    public OperationResult Lock(string folderId)
    {
        var record = _configuration.FindById(folderId);
        if (record is null)
            return OperationResult.Fail("That folder is no longer in the FolderGuard list.", ProtectionState.NotProtected);

        if (!Directory.Exists(record.Path))
        {
            record.State = ProtectionState.Error;
            record.LastError = "Folder not found.";
            _configuration.Save();
            return OperationResult.Fail("The folder no longer exists at its recorded path.", ProtectionState.Error);
        }

        _journal.Write(new JournalEntry
        {
            FolderId = record.Id,
            FolderPath = record.Path,
            Operation = JournalOperation.Lock,
            OriginalDaclSddl = record.OriginalDaclSddl,
            TargetDescription = "locked"
        });

        try
        {
            var hash = AclManager.ApplySecurity(record.Path, AclManager.BuildLockedSecurity(), expectInheritanceProtected: true);
            record.LockedDaclHash = hash;
            record.State = ProtectionState.Locked;
            record.UnlockLogonSid = null;
            record.LastError = null;
            record.LastChangedUtc = DateTimeOffset.Now;
            _configuration.Save();
            _journal.Clear(record.Id);

            _logger.Info($"Locked '{record.Path}'.");
            return OperationResult.Ok(
                $"'{record.DisplayName}' is locked. Its contents are inaccessible until it is unlocked again.",
                ProtectionState.Locked);
        }
        catch (Exception exception)
        {
            _logger.Error($"Lock failed for '{record.Path}'.", exception);
            record.State = ProtectionState.Error;
            record.LastError = exception.Message;
            _configuration.Save();
            return OperationResult.Fail($"The folder could not be locked: {exception.Message}");
        }
    }

    // ---------------------------------------------------------------- password

    public OperationResult ChangePassword(string folderId, string currentPassword, string newPassword, string confirmation)
    {
        var record = _configuration.FindById(folderId);
        if (record is null)
            return OperationResult.Fail("That folder is no longer in the FolderGuard list.", ProtectionState.NotProtected);

        if (!PasswordService.Verify(currentPassword, record.PasswordSalt, record.PasswordHash, record.PasswordIterations))
            return OperationResult.Fail("The current password is incorrect.", record.State);

        if (!PasswordService.IsAcceptable(newPassword, out var passwordError))
            return OperationResult.Fail(passwordError, record.State);

        if (!string.Equals(newPassword, confirmation, StringComparison.Ordinal))
            return OperationResult.Fail("The two new passwords do not match.", record.State);

        if (string.Equals(currentPassword, newPassword, StringComparison.Ordinal))
            return OperationResult.Fail("The new password must be different from the current one.", record.State);

        var material = PasswordService.Create(newPassword, _configuration.Configuration.Settings.Pbkdf2Iterations);
        record.PasswordSalt = material.SaltBase64;
        record.PasswordHash = material.HashBase64;
        record.PasswordIterations = material.Iterations;
        record.LastChangedUtc = DateTimeOffset.Now;

        if (!_configuration.Save())
            return OperationResult.Fail("The new password could not be saved. The previous password is still valid.", record.State);

        _logger.Info($"Password changed for '{record.Path}'.");
        return OperationResult.Ok("Password changed. The folder's permissions were not modified.", record.State);
    }

    // ---------------------------------------------------------------- repair

    /// <summary>Re-applies the locked ACL (used by recovery, "Repair" and "Lock all").</summary>
    public OperationResult ReapplyLock(string folderId)
    {
        var record = _configuration.FindById(folderId);
        if (record is null)
            return OperationResult.Fail("That folder is no longer in the FolderGuard list.", ProtectionState.NotProtected);

        if (!Directory.Exists(record.Path))
        {
            record.State = ProtectionState.Error;
            record.LastError = "Folder not found.";
            _configuration.Save();
            return OperationResult.Fail($"'{record.Path}' no longer exists.", ProtectionState.Error);
        }

        try
        {
            var hash = AclManager.ApplySecurity(record.Path, AclManager.BuildLockedSecurity(), expectInheritanceProtected: true);
            record.LockedDaclHash = hash;
            record.State = ProtectionState.Locked;
            record.UnlockLogonSid = null;
            record.LastError = null;
            record.LastChangedUtc = DateTimeOffset.Now;
            _configuration.Save();
            _logger.Info($"Re-applied the locked permissions to '{record.Path}'.");
            return OperationResult.Ok($"'{record.DisplayName}' is locked.", ProtectionState.Locked);
        }
        catch (Exception exception)
        {
            record.State = ProtectionState.Error;
            record.LastError = exception.Message;
            _configuration.Save();
            _logger.Error($"Could not re-apply the locked permissions to '{record.Path}'.", exception);
            return OperationResult.Fail($"Could not re-apply the locked permissions: {exception.Message}");
        }
    }

    // ---------------------------------------------------------------- remove

    public OperationResult RemoveProtection(string folderId, string password, bool overwriteExternalChanges = false)
    {
        var record = _configuration.FindById(folderId);
        if (record is null)
            return OperationResult.Fail("That folder is no longer in the FolderGuard list.", ProtectionState.NotProtected);

        if (!PasswordService.Verify(password, record.PasswordSalt, record.PasswordHash, record.PasswordIterations))
            return OperationResult.Fail("Incorrect password. Protection was not removed.", record.State);

        if (!Directory.Exists(record.Path))
        {
            // The folder is gone; drop the record but never touch anything on disk.
            _configuration.Configuration.Folders.Remove(record);
            _configuration.Save();
            return OperationResult.Ok("The folder no longer exists, so its record was removed. No files were deleted.", ProtectionState.NotProtected);
        }

        if (string.IsNullOrWhiteSpace(record.OriginalDaclSddl))
        {
            return OperationResult.Fail(
                "There is no stored backup of the original permissions for this folder, so FolderGuard will not guess. " +
                "Use Settings → Open data folder to restore a configuration backup, or reset the permissions manually in Explorer.",
                ProtectionState.Error);
        }

        if (!overwriteExternalChanges)
        {
            var inspection = AclManager.Inspect(record.Path, record);
            var known = inspection.MatchesRecordedState ||
                        (inspection.CurrentDaclHash.Length > 0 &&
                         (string.Equals(inspection.CurrentDaclHash, record.UnlockedDaclHash, StringComparison.OrdinalIgnoreCase) ||
                          string.Equals(inspection.CurrentDaclHash, record.LockedDaclHash, StringComparison.OrdinalIgnoreCase)));

            if (!known && inspection.NeedsRepair)
            {
                return OperationResult.Confirm(
                    "The permissions of this folder were changed outside FolderGuard since it was protected. " +
                    "Removing protection would overwrite those changes with the stored backup. Continue?");
            }
        }

        _journal.Write(new JournalEntry
        {
            FolderId = record.Id,
            FolderPath = record.Path,
            Operation = JournalOperation.Restore,
            OriginalDaclSddl = record.OriginalDaclSddl,
            TargetDescription = "original"
        });

        try
        {
            AclManager.Restore(record.Path, new AclSnapshot(record.OriginalDaclSddl, record.OriginalOwnerSid, record.OriginalGroupSid));

            var check = AclManager.GetSecurity(record.Path);
            var restoredHash = AclManager.ComputeDaclHash(check);
            var expected = AclManager.ComputeDaclHash(SddlToSecurity(record.OriginalDaclSddl));
            if (!string.Equals(restoredHash, expected, StringComparison.Ordinal))
            {
                throw new IOException("The permissions were written but did not read back as the stored backup.");
            }

            _configuration.Configuration.Folders.Remove(record);
            _configuration.Save();
            _journal.Clear(record.Id);

            _logger.Info($"Removed protection from '{record.Path}' and restored the original permissions.");
            return OperationResult.Ok(
                $"Protection removed from '{record.DisplayName}'. The original permissions were restored; no files were deleted or modified.",
                ProtectionState.NotProtected);
        }
        catch (Exception exception)
        {
            _logger.Error($"Could not remove protection from '{record.Path}'.", exception);
            record.State = ProtectionState.Error;
            record.LastError = exception.Message;
            _configuration.Save();
            return OperationResult.Fail(
                $"The original permissions could not be restored ({exception.Message}). The folder stays in the list so you can retry.");
        }
    }

    private static System.Security.AccessControl.DirectorySecurity SddlToSecurity(string sddl)
    {
        var security = new System.Security.AccessControl.DirectorySecurity();
        security.SetSecurityDescriptorSddlForm(sddl, System.Security.AccessControl.AccessControlSections.Access);
        return security;
    }
}
