using System.IO;

namespace FolderGuard.Services;

/// <summary>
/// Minimal append-only log. Never receives passwords, salts or hashes.
/// </summary>
public sealed class Logger
{
    private readonly object _gate = new();
    private readonly string _directory;

    public Logger(string directory)
    {
        _directory = directory;
        try
        {
            Directory.CreateDirectory(_directory);
        }
        catch
        {
            // Logging must never break the application.
        }
    }

    public string LogDirectory => _directory;

    public void Info(string message) => Write("INFO ", message);

    public void Warn(string message) => Write("WARN ", message);

    public void Error(string message, Exception? exception = null)
    {
        var detail = exception is null ? message : $"{message} :: {exception.GetType().Name}: {exception.Message}";
        Write("ERROR", detail);
    }

    private void Write(string level, string message)
    {
        try
        {
            var line = $"{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss.fff zzz} [{level}] {message}";
            lock (_gate)
            {
                var path = Path.Combine(_directory, $"folderguard-{DateTimeOffset.Now:yyyyMMdd}.log");
                File.AppendAllText(path, line + Environment.NewLine);
            }
        }
        catch
        {
            // Ignore logging failures.
        }
    }
}
