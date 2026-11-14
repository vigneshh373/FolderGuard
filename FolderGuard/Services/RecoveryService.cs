using System.IO;
using FolderGuard.Models;

namespace FolderGuard.Services;

public sealed class RecoveryReport
{
    public List<string> Messages { get; } = new();
    public bool ConfigurationFailure { get; init; }
    public bool RepairedFolders { get; set; }

    public string Summary => Messages.Count == 0 ? string.Empty : string.Join(" ", Messages);
}

/// <summary>
/// Brings every protected folder back to a known-safe state at application start.
///
/// This is the second half of the reboot guarantee. The primary guarantee is architectural:
/// unlocked access is granted to the logon-session SID, which no longer exists in any token
/// after a sign-out or restart, so the folder is already inaccessible before FolderGuard runs.
/// Recovery then removes the inert leftover ACE, finishes interrupted operations and re-locks
/// folders whose ACL was altered.
/// </summary>
public sealed class RecoveryService
{
    private readonly ConfigurationService _configuration;
    private readonly FolderProtectionService _protection;
    private readonly JournalStore _journal;
    private readonly Logger _logger;

    public RecoveryService(
        ConfigurationService configuration,
        FolderProtectionService protection,
        JournalStore journal,
        Logger logger)
    {
        _configuration = configuration;
        _protection = protection;
        _journal = journal;
        _logger = logger;
    }

    public RecoveryReport Run()
    {
        if (_configuration.LoadStatus == ConfigurationLoadStatus.Failed)
        {
            var failed = new RecoveryReport { ConfigurationFailure = true };
            failed.Messages.Add(
                "The configuration store could not be read. No folder permissions were touched. " +
                "See Settings → Open data folder for the log and the backup file.");
            return failed;
        }

        var report = new RecoveryReport();
        if (_configuration.LoadStatus == ConfigurationLoadStatus.RecoveredFromBackup)
            report.Messages.Add("The configuration backup was loaded because the primary store was unreadable.");

        ReplayJournal(report);
        ReconcileRecords(report);
        _configuration.Save();
        return report;
    }

    /// <summary>Completes or safely aborts operations that were interrupted mid-flight.</summary>
    private void ReplayJournal(RecoveryReport report)
    {
        foreach (var entry in _journal.ReadAll())
        {
            var record = _configuration.FindById(entry.FolderId);

            try
            {
                if (!Directory.Exists(entry.FolderPath))
                {
                    _journal.Clear(entry.FolderId);
                    continue;
                }

                switch (entry.Operation)
                {
                    case JournalOperation.Restore:
                        {
                            // A removal was interrupted. If the ACL already equals the original, finish
                            // the removal; otherwise keep the record and leave the folder locked.
                            if (record is not null && !string.IsNullOrWhiteSpace(entry.OriginalDaclSddl))
                            {
                                var current = AclManager.ComputeDaclHash(AclManager.GetSecurity(entry.FolderPath));
                                var original = AclManager.ComputeDaclHash(SddlToSecurity(entry.OriginalDaclSddl));
                                if (string.Equals(current, original, StringComparison.OrdinalIgnoreCase))
                                {
                                    _configuration.Configuration.Folders.Remove(record);
                                    _journal.Clear(entry.FolderId);
                                    report.Messages.Add($"Finished removing protection from '{entry.FolderPath}'.");
                                    break;
                                }
                            }

                            if (record is not null)
                                _protection.ReapplyLock(record.Id);

                            _journal.Clear(entry.FolderId);
                            report.Messages.Add($"An interrupted removal for '{entry.FolderPath}' was recovered; the folder stays protected.");
                            report.RepairedFolders = true;
                            break;
                        }

                    case JournalOperation.Protect:
                    case JournalOperation.Lock:
                        {
                            if (record is not null)
                            {
                                _protection.ReapplyLock(record.Id);
                                report.Messages.Add($"Re-applied the locked permissions to '{entry.FolderPath}' after an interrupted operation.");
                                report.RepairedFolders = true;
                            }

                            _journal.Clear(entry.FolderId);
                            break;
                        }

                    case JournalOperation.Unlock:
                        {
                            // Never leave a stale session grant behind: the safe state is locked.
                            if (record is not null)
                            {
                                _protection.ReapplyLock(record.Id);
                                report.Messages.Add($"'{entry.FolderPath}' was left locked after an interrupted unlock.");
                                report.RepairedFolders = true;
                            }

                            _journal.Clear(entry.FolderId);
                            break;
                        }
                }
            }
            catch (Exception exception)
            {
                _logger.Error($"Recovery of journal entry '{entry.FolderPath}' failed.", exception);
                report.Messages.Add($"Recovery of '{entry.FolderPath}' failed: {exception.Message}");
            }
        }
    }

    /// <summary>
    /// Re-derives the live state of every record. Anything that is not a valid unlock for the
    /// *current* Windows session is forced back to the locked ACL.
    /// </summary>
    private void ReconcileRecords(RecoveryReport report)
    {
        foreach (var record in _configuration.Configuration.Folders.ToList())
        {
            try
            {
                if (!Directory.Exists(record.Path))
                {
                    record.State = ProtectionState.Error;
                    record.LastError = "The folder no longer exists at this path.";
                    continue;
                }

                var inspection = AclManager.Inspect(record.Path, record);

                if (inspection.State == ProtectionState.Unlocked)
                {
                    record.State = ProtectionState.Unlocked;
                    record.LastError = null;
                    continue;
                }

                // Locked, stale-session, tampered or unknown: enforce the locked ACL.
                var needsEnforcement = inspection.NeedsRepair || !inspection.MatchesRecordedState ||
                                       record.State == ProtectionState.Unlocked;

                if (inspection.State == ProtectionState.Error && !inspection.NeedsRepair)
                {
                    record.State = ProtectionState.Error;
                    record.LastError = inspection.Message;
                    continue;
                }

                if (needsEnforcement)
                {
                    var result = _protection.ReapplyLock(record.Id);
                    if (result.Success)
                    {
                        report.RepairedFolders = true;
                        if (inspection.NeedsRepair)
                        {
                            report.Messages.Add(
                                $"'{record.DisplayName}' was re-locked at start-up and its locked permission set was refreshed.");
                        }
                    }
                    else
                    {
                        report.Messages.Add($"'{record.DisplayName}' could not be re-locked: {result.Message}");
                    }
                }
                else
                {
                    record.State = ProtectionState.Locked;
                    record.LastError = null;
                }
            }
            catch (Exception exception)
            {
                _logger.Error($"Could not reconcile '{record.Path}' at startup.", exception);
                report.Messages.Add($"'{record.Path}' could not be verified at startup: {exception.Message}");
            }
        }
    }

    private static System.Security.AccessControl.DirectorySecurity SddlToSecurity(string sddl)
    {
        var security = new System.Security.AccessControl.DirectorySecurity();
        security.SetSecurityDescriptorSddlForm(sddl, System.Security.AccessControl.AccessControlSections.Access);
        return security;
    }
}
