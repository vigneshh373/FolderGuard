using System.IO;
using System.Text.Json;

namespace FolderGuard.Services;

/// <summary>
/// Reads the optional appsettings.json that ships next to the executable.
/// It only supplies defaults for a fresh installation; all mutable state lives in
/// the DPAPI-protected configuration store.
/// </summary>
public sealed class AppOptions
{
    public int DefaultPbkdf2Iterations { get; init; } = PasswordService.DefaultIterations;
    public int MinimumPasswordLength { get; init; } = PasswordService.MinimumPasswordLength;

    /// <summary>Minutes without keyboard/mouse activity before unlocked folders lock again.</summary>
    public int AutoLockIdleMinutes { get; init; } = 5;

    public string DataDirectoryName { get; init; } = "FolderGuard";

    public static AppOptions Load()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        try
        {
            if (!File.Exists(path))
                return new AppOptions();

            var document = JsonDocument.Parse(File.ReadAllText(path));
            if (!document.RootElement.TryGetProperty("FolderGuard", out var section))
                return new AppOptions();

            int ReadInt(string name, int fallback) =>
                section.TryGetProperty(name, out var value) && value.TryGetInt32(out var parsed) ? parsed : fallback;

            string ReadString(string name, string fallback) =>
                section.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
                    ? value.GetString() ?? fallback
                    : fallback;

            return new AppOptions
            {
                DefaultPbkdf2Iterations = Math.Max(10_000, ReadInt("defaultPbkdf2Iterations", PasswordService.DefaultIterations)),
                MinimumPasswordLength = Math.Max(6, ReadInt("minimumPasswordLength", PasswordService.MinimumPasswordLength)),
                AutoLockIdleMinutes = Math.Max(1, ReadInt("autoLockIdleMinutes", 5)),
                DataDirectoryName = ReadString("dataDirectoryName", "FolderGuard")
            };
        }
        catch
        {
            return new AppOptions();
        }
    }
}
