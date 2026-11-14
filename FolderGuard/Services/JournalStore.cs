using System.IO;
using System.Text.Json;

namespace FolderGuard.Services;

public enum JournalOperation
{
    Protect,
    Unlock,
    Lock,
    Restore
}

/// <summary>
/// Intent record written *before* a security descriptor is modified and removed after the
/// operation completed. If FolderGuard (or the machine) dies mid-operation, the next start
/// finds the entry and brings the folder back to a known safe state.
/// Contains no secrets: only paths, operation names and the ACL backup.
/// </summary>
public sealed class JournalEntry
{
    public string FolderId { get; set; } = string.Empty;
    public string FolderPath { get; set; } = string.Empty;
    public JournalOperation Operation { get; set; }
    public string OriginalDaclSddl { get; set; } = string.Empty;
    public string TargetDescription { get; set; } = string.Empty;
    public DateTimeOffset StartedUtc { get; set; } = DateTimeOffset.Now;
}

public sealed class JournalStore
{
    private readonly Logger _logger;
    private readonly string _directory;

    public JournalStore(string directory, Logger logger)
    {
        _directory = directory;
        _logger = logger;
        try
        {
            Directory.CreateDirectory(_directory);
        }
        catch (Exception exception)
        {
            _logger.Error("Could not create the journal directory", exception);
        }
    }

    public void Write(JournalEntry entry)
    {
        try
        {
            Directory.CreateDirectory(_directory);
            var path = PathFor(entry.FolderId);
            var json = JsonSerializer.Serialize(entry, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path + ".tmp", json);
            File.Move(path + ".tmp", path, overwrite: true);
        }
        catch (Exception exception)
        {
            _logger.Error("Could not write the recovery journal", exception);
        }
    }

    public void Clear(string folderId)
    {
        try
        {
            var path = PathFor(folderId);
            if (File.Exists(path))
                File.Delete(path);
        }
        catch (Exception exception)
        {
            _logger.Warn("Could not clear the recovery journal entry: " + exception.Message);
        }
    }

    public IReadOnlyList<JournalEntry> ReadAll()
    {
        var entries = new List<JournalEntry>();
        try
        {
            if (!Directory.Exists(_directory))
                return entries;

            foreach (var path in Directory.EnumerateFiles(_directory, "*.json"))
            {
                try
                {
                    var entry = JsonSerializer.Deserialize<JournalEntry>(File.ReadAllText(path));
                    if (entry is not null && !string.IsNullOrWhiteSpace(entry.FolderPath))
                        entries.Add(entry);
                }
                catch (Exception exception)
                {
                    _logger.Warn($"Ignoring unreadable journal entry '{Path.GetFileName(path)}': {exception.Message}");
                }
            }
        }
        catch (Exception exception)
        {
            _logger.Error("Could not enumerate the journal directory", exception);
        }

        return entries;
    }

    private string PathFor(string folderId) => Path.Combine(_directory, folderId + ".json");
}
