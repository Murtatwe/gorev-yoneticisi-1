using System.Runtime.InteropServices;
using System.Text;
using GorevYoneticisi.App.Native;
using GorevYoneticisi.Core;

namespace GorevYoneticisi.App.Services;

/// <summary>Looks up a process's executable path (cached per PID + creation time) and its command line.</summary>
internal sealed class ProcessDetails
{
    private readonly Dictionary<(int Pid, long Create), string?> _paths = new();
    private readonly Dictionary<(int Pid, long Create), long> _failedAt = new();
    private static readonly long RetryTicks = TimeSpan.FromSeconds(10).Ticks;
    private Dictionary<string, string> _deviceMap = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _deviceMapAge = DateTime.MinValue;
    private readonly string _windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private readonly object _lock = new();

    public string? GetPath(int pid, long createTime)
    {
        if (pid <= 4) return null;
        lock (_lock)
        {
            if (_paths.TryGetValue((pid, createTime), out var cached)) return cached;
            // Failures (very young process, transient error) are retried, not cached forever.
            if (_failedAt.TryGetValue((pid, createTime), out long at) && DateTime.UtcNow.Ticks - at < RetryTicks) return null;
        }
        string? path = QueryPath(pid);
        lock (_lock)
        {
            if (path is null) _failedAt[(pid, createTime)] = DateTime.UtcNow.Ticks;
            else
            {
                _paths[(pid, createTime)] = path;
                _failedAt.Remove((pid, createTime));
            }
        }
        return path;
    }

    /// <summary>Removes cache entries for processes that no longer exist.</summary>
    public void Prune(IEnumerable<(int Pid, long Create)> alive)
    {
        var keep = alive.ToHashSet();
        lock (_lock)
        {
            foreach (var key in _paths.Keys.Where(k => !keep.Contains(k)).ToList()) _paths.Remove(key);
            foreach (var key in _failedAt.Keys.Where(k => !keep.Contains(k)).ToList()) _failedAt.Remove(key);
        }
    }

    public string? QueryPath(int pid)
    {
        IntPtr h = Kernel32.OpenProcess(Kernel32.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h != IntPtr.Zero)
        {
            try
            {
                var sb = new StringBuilder(1024);
                int size = sb.Capacity;
                if (Kernel32.QueryFullProcessImageNameW(h, 0, sb, ref size)) return sb.ToString(0, size);
            }
            finally
            {
                Kernel32.CloseHandle(h);
            }
        }
        // Fallback that works without opening the process (protected processes).
        string? nt = QueryNtImagePath(pid);
        return nt is null ? null : DevicePaths.ToDosPath(nt, DeviceMap(), _windowsDir);
    }

    private static unsafe string? QueryNtImagePath(int pid)
    {
        ushort bytes = 1024;
        for (int attempt = 0; attempt < 2; attempt++)
        {
            IntPtr text = Marshal.AllocHGlobal(bytes);
            try
            {
                var info = new Ntdll.SYSTEM_PROCESS_ID_INFORMATION
                {
                    ProcessId = (IntPtr)pid,
                    ImageName = new Ntdll.UNICODE_STRING { Length = 0, MaximumLength = bytes, Buffer = text },
                };
                uint status = Ntdll.NtQuerySystemInformation(Ntdll.SystemProcessIdInformation, (IntPtr)(&info), sizeof(Ntdll.SYSTEM_PROCESS_ID_INFORMATION), out _);
                if (status == Ntdll.STATUS_INFO_LENGTH_MISMATCH && info.ImageName.MaximumLength > bytes)
                {
                    bytes = info.ImageName.MaximumLength; // the kernel reports the size it needs
                    continue;
                }
                if (status != Ntdll.STATUS_SUCCESS || info.ImageName.Length == 0) return null;
                return new string((char*)text, 0, info.ImageName.Length / 2);
            }
            finally
            {
                Marshal.FreeHGlobal(text);
            }
        }
        return null;
    }

    public static unsafe string? QueryCommandLine(int pid)
    {
        IntPtr h = Kernel32.OpenProcess(Kernel32.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return null;
        try
        {
            int size = 4096;
            for (int i = 0; i < 4; i++)
            {
                IntPtr buf = Marshal.AllocHGlobal(size);
                try
                {
                    uint status = Ntdll.NtQueryInformationProcess(h, Ntdll.ProcessCommandLineInformation, buf, size, out int needed);
                    if (status == Ntdll.STATUS_INFO_LENGTH_MISMATCH || status == Ntdll.STATUS_BUFFER_OVERFLOW || status == Ntdll.STATUS_BUFFER_TOO_SMALL)
                    {
                        size = Math.Max(size * 2, needed);
                        continue;
                    }
                    if (status != Ntdll.STATUS_SUCCESS) return null;
                    var us = (Ntdll.UNICODE_STRING*)buf;
                    return us->Length == 0 ? "" : new string((char*)us->Buffer, 0, us->Length / 2);
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
            return null;
        }
        finally
        {
            Kernel32.CloseHandle(h);
        }
    }

    private Dictionary<string, string> DeviceMap()
    {
        lock (_lock)
        {
            if (DateTime.UtcNow - _deviceMapAge < TimeSpan.FromMinutes(1)) return _deviceMap;
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            uint drives = Kernel32.GetLogicalDrives();
            var sb = new StringBuilder(1024);
            for (int i = 0; i < 26; i++)
            {
                if ((drives & (1u << i)) == 0) continue;
                string drive = $"{(char)('A' + i)}:";
                sb.Clear();
                if (Kernel32.QueryDosDeviceW(drive, sb, sb.Capacity) > 0)
                {
                    string device = sb.ToString().Split('\0')[0];
                    if (device.Length > 0) map[device] = drive;
                }
            }
            _deviceMap = map;
            _deviceMapAge = DateTime.UtcNow;
            return map;
        }
    }
}
