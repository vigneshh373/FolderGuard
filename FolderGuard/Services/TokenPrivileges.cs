using System.Runtime.InteropServices;

namespace FolderGuard.Services;

/// <summary>
/// Enables the backup/restore privileges in FolderGuard's own elevated token.
///
/// This is what makes the hardening in <see cref="AclManager.BuildLockedSecurity"/> viable:
/// the locked DACL grants Administrators only READ_CONTROL (no data access, no WRITE_DAC), so
/// Explorer's "Continue to permanently get access" elevation prompt cannot re-grant access.
/// FolderGuard itself can still write the security descriptor because SeRestorePrivilege
/// bypasses the DACL check for setting the owner/DACL, and SeBackupPrivilege bypasses it for
/// reading security information.
/// </summary>
internal static class TokenPrivileges
{
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private const int SePrivilegeEnabled = 0x00000002;
    private const int ErrorNotAllAssigned = 1300;

    private static readonly string[] RequiredPrivileges =
    {
        "SeRestorePrivilege",
        "SeBackupPrivilege",
        "SeTakeOwnershipPrivilege"
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivilegesState
    {
        public int PrivilegeCount;
        public Luid Luid;
        public int Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool LookupPrivilegeValue(string? systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle,
        bool disableAllPrivileges,
        ref TokenPrivilegesState newState,
        int bufferLength,
        IntPtr previousState,
        IntPtr returnLength);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    /// <summary>Enables every required privilege; reports the ones that were refused.</summary>
    public static bool Enable(out string failure)
    {
        failure = string.Empty;
        var refused = new List<string>();

        if (!OpenProcessToken(GetCurrentProcess(), TokenAdjustPrivileges | TokenQuery, out var token))
        {
            failure = "OpenProcessToken failed (Win32 " + Marshal.GetLastWin32Error() + ")";
            return false;
        }

        try
        {
            foreach (var name in RequiredPrivileges)
            {
                if (!LookupPrivilegeValue(null, name, out var luid))
                {
                    refused.Add(name);
                    continue;
                }

                var state = new TokenPrivilegesState
                {
                    PrivilegeCount = 1,
                    Luid = luid,
                    Attributes = SePrivilegeEnabled
                };

                Marshal.GetLastWin32Error();
                var adjusted = AdjustTokenPrivileges(token, false, ref state, 0, IntPtr.Zero, IntPtr.Zero);
                var error = Marshal.GetLastWin32Error();

                if (!adjusted || error == ErrorNotAllAssigned)
                    refused.Add(name);
            }
        }
        finally
        {
            CloseHandle(token);
        }

        if (refused.Count > 0)
        {
            failure = "not available: " + string.Join(", ", refused);
            return false;
        }

        return true;
    }
}
