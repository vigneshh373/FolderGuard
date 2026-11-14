using System.Runtime.InteropServices;

namespace FolderGuard.Services;

/// <summary>
/// Reads how long the machine has been without keyboard or mouse input, using the same
/// system-wide value Windows uses for idle detection.
/// </summary>
internal static class IdleMonitor
{
    [StructLayout(LayoutKind.Sequential)]
    private struct LastInputInfo
    {
        public uint Size;
        public uint Time;
    }

    [DllImport("user32.dll")]
    private static extern bool GetLastInputInfo(ref LastInputInfo info);

    /// <summary>Time since the last keyboard or mouse input anywhere in the session.</summary>
    public static TimeSpan GetIdleTime()
    {
        var info = new LastInputInfo { Size = (uint)Marshal.SizeOf<LastInputInfo>() };
        if (!GetLastInputInfo(ref info))
            return TimeSpan.Zero;

        var idleMilliseconds = unchecked((uint)Environment.TickCount - info.Time);
        return TimeSpan.FromMilliseconds(idleMilliseconds);
    }
}
