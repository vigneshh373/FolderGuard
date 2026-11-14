using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using FolderGuard.Models;

namespace FolderGuard.Services;

public enum ConfigurationLoadStatus
{
    Loaded,
    CreatedNew,
    RecoveredFromBackup,
    Failed
}

/// <summary>
/// Persistent store for protected-folder records. The document is serialised to JSON,
/// encrypted with DPAPI (machine scope) and written atomically to
/// %ProgramData%\FolderGuard\config.dat. The containing directory is restricted to
/// SYSTEM and Administrators.
///
/// If the store cannot be read, no permission is ever changed: the application runs in a
/// read-only/repair mode until the operator resolves it.
/// </summary>
public sealed class ConfigurationService
{
    private const string EntropyText = "FolderGuard.Configuration.v1";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly AppOptions _options;
    private readonly Logger _logger;

    public string DataDirectory { get; }
    public string LogDirectory { get; }
    public string JournalDirectory { get; }
    public string ConfigurationPath => Path.Combine(DataDirectory, "config.dat");
    public string BackupPath => Path.Combine(DataDirectory, "config.dat.bak");

    public FolderConfiguration Configuration { get; private set; } = new();
    public ConfigurationLoadStatus LoadStatus { get; private set; } = ConfigurationLoadStatus.CreatedNew;
    public string? LoadError { get; private set; }

    public ConfigurationService(AppOptions options, Logger logger, string? dataDirectoryOverride = null)
    {
        _options = options;
        _logger = logger;

        DataDirectory = dataDirectoryOverride ??
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), options.DataDirectoryName);
        LogDirectory = Path.Combine(DataDirectory, "logs");
        JournalDirectory = Path.Combine(DataDirectory, "journal");

        EnsureDirectories();
        Load();
    }

    public ProtectedFolder? FindById(string id) =>
        Configuration.Folders.FirstOrDefault(folder => string.Equals(folder.Id, id, StringComparison.Ordinal));

    public ProtectedFolder? FindByPath(string path) =>
        Configuration.Folders.FirstOrDefault(folder => string.Equals(
            folder.Path.TrimEnd('\\'), path.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase));

    // ---------------------------------------------------------------- load

    private void Load()
    {
        if (!File.Exists(ConfigurationPath) && !File.Exists(BackupPath))
        {
            Configuration = new FolderConfiguration
            {
                Settings = new AppSettings
                {
                    Pbkdf2Iterations = _options.DefaultPbkdf2Iterations
                }
            };
            LoadStatus = ConfigurationLoadStatus.CreatedNew;

            if (!TrySave(out var createError))
            {
                LoadStatus = ConfigurationLoadStatus.Failed;
                LoadError = "The configuration store could not be created: " + createError;
            }

            return;
        }

        var errors = new List<string>();

        foreach (var candidate in new[] { ConfigurationPath, BackupPath })
        {
            if (!File.Exists(candidate))
                continue;

            try
            {
                Configuration = ReadProtectedDocument(candidate);
                Normalize(Configuration);
                LoadStatus = referenceEqualsPath(candidate, ConfigurationPath)
                    ? ConfigurationLoadStatus.Loaded
                    : ConfigurationLoadStatus.RecoveredFromBackup;

                if (LoadStatus == ConfigurationLoadStatus.RecoveredFromBackup)
                    LoadError = "The primary configuration file was unreadable, so the backup copy was loaded.";

                if (errors.Count > 0)
                    _logger.Warn("Configuration loaded after earlier read failures: " + string.Join(" | ", errors));

                return;
            }
            catch (Exception exception)
            {
                errors.Add($"{Path.GetFileName(candidate)}: {exception.GetType().Name}: {exception.Message}");
                _logger.Error($"Could not read '{candidate}'", exception);
            }
        }

        Configuration = new FolderConfiguration();
        LoadStatus = ConfigurationLoadStatus.Failed;
        LoadError =
            "FolderGuard could not read its configuration store, so no folder permissions were changed. " +
            "Details were written to the log. Restore a copy of '%ProgramData%\\FolderGuard\\config.dat' " +
            "or remove the store to start over (existing ACLs are not modified by removing it).";
    }

    private static bool referenceEqualsPath(string a, string b) =>
        string.Equals(Path.GetFullPath(a), Path.GetFullPath(b), StringComparison.OrdinalIgnoreCase);

    private static FolderConfiguration ReadProtectedDocument(string path)
    {
        var protectedBytes = File.ReadAllBytes(path);
        if (protectedBytes.Length == 0)
            throw new InvalidDataException("The file is empty.");

        var entropy = Encoding.UTF8.GetBytes(EntropyText);
        var plain = ProtectedData.Unprotect(protectedBytes, entropy, DataProtectionScope.LocalMachine);
        try
        {
            var document = JsonSerializer.Deserialize<FolderConfiguration>(plain, JsonOptions);
            if (document is null)
                throw new InvalidDataException("The configuration document is empty.");
            return document;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plain);
        }
    }

    private static void Normalize(FolderConfiguration configuration)
    {
        configuration.Folders ??= new List<ProtectedFolder>();
        configuration.Settings ??= new AppSettings();

        foreach (var folder in configuration.Folders)
        {
            folder.Id = string.IsNullOrWhiteSpace(folder.Id) ? Guid.NewGuid().ToString("N") : folder.Id;
            folder.Path ??= string.Empty;
            folder.PasswordSalt ??= string.Empty;
            folder.PasswordHash ??= string.Empty;
            folder.OriginalDaclSddl ??= string.Empty;
            folder.LockedDaclHash ??= string.Empty;
            folder.UnlockedDaclHash ??= string.Empty;
        }
    }

    // ---------------------------------------------------------------- save

    public bool Save() => TrySave(out _);

    public bool TrySave(out string error)
    {
        error = string.Empty;

        if (LoadStatus == ConfigurationLoadStatus.Failed)
        {
            error = "Refusing to overwrite a configuration store that could not be read.";
            return false;
        }

        try
        {
            EnsureDirectories();

            Configuration.SchemaVersion = 1;
            var json = JsonSerializer.SerializeToUtf8Bytes(Configuration, JsonOptions);
            var entropy = Encoding.UTF8.GetBytes(EntropyText);
            byte[] protectedBytes;
            try
            {
                protectedBytes = ProtectedData.Protect(json, entropy, DataProtectionScope.LocalMachine);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(json);
            }

            var temporaryPath = ConfigurationPath + ".tmp";
            File.WriteAllBytes(temporaryPath, protectedBytes);
            RestrictFile(temporaryPath);

            if (File.Exists(ConfigurationPath))
            {
                File.Replace(temporaryPath, ConfigurationPath, BackupPath, ignoreMetadataErrors: true);
            }
            else
            {
                File.Move(temporaryPath, ConfigurationPath, overwrite: true);
            }

            RestrictFile(ConfigurationPath);
            if (File.Exists(BackupPath))
                RestrictFile(BackupPath);

            return true;
        }
        catch (Exception exception)
        {
            error = exception.Message;
            _logger.Error("Could not save the configuration store", exception);
            return false;
        }
    }

    public void Reload()
    {
        Load();
    }

    // ---------------------------------------------------------------- directory / file hardening

    private void EnsureDirectories()
    {
        Directory.CreateDirectory(DataDirectory);
        Directory.CreateDirectory(LogDirectory);
        Directory.CreateDirectory(JournalDirectory);

        try
        {
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(
                system, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                administrators, FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));

            new DirectoryInfo(DataDirectory).SetAccessControl(security);
        }
        catch (Exception exception)
        {
            // Not fatal: the store is still DPAPI encrypted, and this can fail on unusual volumes.
            _logger.Warn("Could not restrict the configuration directory permissions: " + exception.Message);
        }
    }

    private static void RestrictFile(string path)
    {
        try
        {
            var system = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
            var administrators = new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null);

            var security = new FileSecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(
                system, FileSystemRights.FullControl, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                administrators, FileSystemRights.FullControl, AccessControlType.Allow));

            new FileInfo(path).SetAccessControl(security);
        }
        catch
        {
            // Best effort.
        }
    }
}
