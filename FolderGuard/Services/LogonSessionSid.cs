using System.Runtime.InteropServices;
using System.Security.Principal;

namespace FolderGuard.Services;

/// <summary>
/// Determines the logon-session SID (S-1-5-5-x-y) of the current interactive session.
///
/// This SID is what makes an unlock self-expiring: it exists only in tokens of the current
/// logon session, so the grant dies on sign-out/restart. The managed
/// <see cref="WindowsIdentity.Groups"/> view does not always surface it, so the authoritative
/// TokenGroups API is used first, with two fallbacks.
/// </summary>
internal static class LogonSessionSid
{
    private const int TokenGroupsClass = 2;
    private const int TokenStatisticsClass = 10;
    private const uint TokenQuery = 0x0008;
    private const uint SeGroupLogonId = 0xC0000000;

    public static SecurityIdentifier? Get(out string diagnostics)
    {
        var notes = new List<string>();

        var fromToken = ReadFromTokenGroups(notes);
        if (fromToken is not null)
        {
            diagnostics = "source=token-groups; " + string.Join("; ", notes);
            return fromToken;
        }

        var fromIdentity = ReadFromWindowsIdentity(notes);
        if (fromIdentity is not null)
        {
            diagnostics = "source=windows-identity; " + string.Join("; ", notes);
            return fromIdentity;
        }

        var fromLuid = ReadFromTokenStatistics(notes);
        if (fromLuid is not null)
        {
            diagnostics = "source=token-statistics; " + string.Join("; ", notes);
            return fromLuid;
        }

        diagnostics = string.Join("; ", notes);
        return null;
    }

    // ---------------------------------------------------------------- 1. TokenGroups (authoritative)

    private static SecurityIdentifier? ReadFromTokenGroups(List<string> notes)
    {
        var token = IntPtr.Zero;
        var buffer = IntPtr.Zero;

        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out token))
            {
                notes.Add("OpenProcessToken=" + Marshal.GetLastWin32Error());
                return null;
            }

            GetTokenInformation(token, TokenGroupsClass, IntPtr.Zero, 0, out var size);
            if (size <= 0)
            {
                notes.Add("TokenGroups length=0");
                return null;
            }

            buffer = Marshal.AllocHGlobal(size);
            if (!GetTokenInformation(token, TokenGroupsClass, buffer, size, out size))
            {
                notes.Add("GetTokenInformation(TokenGroups)=" + Marshal.GetLastWin32Error());
                return null;
            }

            var count = Marshal.ReadInt32(buffer);
            notes.Add("groups=" + count);

            var entrySize = IntPtr.Size == 8 ? 16 : 8;
            var firstEntry = IntPtr.Size == 8 ? 8 : 4;

            for (var index = 0; index < count; index++)
            {
                var entry = IntPtr.Add(buffer, firstEntry + index * entrySize);
                var sidPointer = Marshal.ReadIntPtr(entry);
                var attributes = (uint)Marshal.ReadInt32(IntPtr.Add(entry, IntPtr.Size));
                var text = SidToString(sidPointer);

                if (text is null)
                    continue;

                var isLogonAttribute = (attributes & SeGroupLogonId) != 0;
                var isLogonSidShape = text.StartsWith("S-1-5-5-", StringComparison.Ordinal) && text != "S-1-5-5-0";

                if (!isLogonAttribute && !isLogonSidShape)
                    continue;

                try
                {
                    notes.Add("logonSid=" + text);
                    return new SecurityIdentifier(text);
                }
                catch
                {
                    notes.Add("unparsable=" + text);
                }
            }

            notes.Add("no logon SID in token groups");
            return null;
        }
        catch (Exception exception)
        {
            notes.Add("TokenGroups error=" + exception.Message);
            return null;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(buffer);
            if (token != IntPtr.Zero)
                CloseHandle(token);
        }
    }

    // ---------------------------------------------------------------- 2. Managed identity

    private static SecurityIdentifier? ReadFromWindowsIdentity(List<string> notes)
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var groups = identity.Groups;
            if (groups is null)
            {
                notes.Add("WindowsIdentity.Groups=null");
                return null;
            }

            var count = 0;
            foreach (var sid in groups.OfType<SecurityIdentifier>())
            {
                count++;
                if (IsLogonSessionSid(sid))
                {
                    notes.Add("identityLogonSid=" + sid.Value);
                    return sid;
                }
            }

            notes.Add("identityGroups=" + count + " (no S-1-5-5-)");
            return null;
        }
        catch (Exception exception)
        {
            notes.Add("WindowsIdentity error=" + exception.Message);
            return null;
        }
    }

    // ---------------------------------------------------------------- 3. Logon LUID

    private static SecurityIdentifier? ReadFromTokenStatistics(List<string> notes)
    {
        var token = IntPtr.Zero;
        var buffer = IntPtr.Zero;

        try
        {
            if (!OpenProcessToken(GetCurrentProcess(), TokenQuery, out token))
            {
                notes.Add("stats OpenProcessToken=" + Marshal.GetLastWin32Error());
                return null;
            }

            GetTokenInformation(token, TokenStatisticsClass, IntPtr.Zero, 0, out var size);
            if (size <= 0)
            {
                notes.Add("TokenStatistics length=0");
                return null;
            }

            buffer = Marshal.AllocHGlobal(size);
            if (!GetTokenInformation(token, TokenStatisticsClass, buffer, size, out size))
            {
                notes.Add("GetTokenInformation(TokenStatistics)=" + Marshal.GetLastWin32Error());
                return null;
            }

            // TOKEN_STATISTICS: TokenId (LUID, 8), AuthenticationId (LUID, 8), ...
            var low = (uint)Marshal.ReadInt32(buffer, 8);
            var high = (uint)Marshal.ReadInt32(buffer, 12);
            var value = $"S-1-5-5-{high}-{low}";

            notes.Add("luidLogonSid=" + value);
            return new SecurityIdentifier(value);
        }
        catch (Exception exception)
        {
            notes.Add("TokenStatistics error=" + exception.Message);
            return null;
        }
        finally
        {
            if (buffer != IntPtr.Zero)
                Marshal.FreeHGlobal(buffer);
            if (token != IntPtr.Zero)
                CloseHandle(token);
        }
    }

    public static bool IsLogonSessionSid(SecurityIdentifier sid) =>
        sid.Value.StartsWith("S-1-5-5-", StringComparison.Ordinal) && sid.Value != "S-1-5-5-0";

    private static string? SidToString(IntPtr sid)
    {
        if (sid == IntPtr.Zero)
            return null;

        IntPtr text = IntPtr.Zero;
        try
        {
            if (!ConvertSidToStringSid(sid, out text) || text == IntPtr.Zero)
                return null;

            return Marshal.PtrToStringUni(text);
        }
        finally
        {
            if (text != IntPtr.Zero)
                LocalFree(text);
        }
    }

    // ---------------------------------------------------------------- native

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle, int tokenInformationClass, IntPtr tokenInformation, int tokenInformationLength, out int returnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertSidToStringSid(IntPtr sid, out IntPtr stringSid);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr LocalFree(IntPtr handle);
}
