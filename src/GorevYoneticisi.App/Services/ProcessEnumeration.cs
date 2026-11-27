using System.Runtime.InteropServices;
using GorevYoneticisi.App.Native;
using GorevYoneticisi.Core.Metrics;

namespace GorevYoneticisi.App.Services;

/// <summary>Independent ways of listing processes, used both for display and for cross-view (hidden process) detection.</summary>
internal static class ProcessEnumeration
{
    private static int _lastBufferSize = 512 * 1024;

    /// <summary>Primary list: NtQuerySystemInformation(SystemProcessInformation). Gives everything without opening processes.</summary>
    public static unsafe List<RawProcessSample> QueryPrimary()
    {
        int size = _lastBufferSize;
        for (int attempt = 0; attempt < 8; attempt++)
        {
            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint status = Ntdll.NtQuerySystemInformation(Ntdll.SystemProcessInformation, buffer, size, out int needed);
                if (status == Ntdll.STATUS_INFO_LENGTH_MISMATCH || status == Ntdll.STATUS_BUFFER_TOO_SMALL)
                {
                    size = Math.Max(size * 2, needed + 64 * 1024);
                    continue;
                }
                if (status != Ntdll.STATUS_SUCCESS)
                    throw new InvalidOperationException($"NtQuerySystemInformation başarısız: 0x{status:X8}");

                _lastBufferSize = size;
                return Parse((byte*)buffer, size);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        throw new InvalidOperationException("İşlem listesi için yeterli bellek ayrılamadı.");
    }

    private static unsafe List<RawProcessSample> Parse(byte* buffer, int size)
    {
        var result = new List<RawProcessSample>(400);
        long offset = 0;
        while (offset + sizeof(Ntdll.SYSTEM_PROCESS_INFORMATION) <= size)
        {
            var info = (Ntdll.SYSTEM_PROCESS_INFORMATION*)(buffer + offset);
            int pid = (int)(long)info->UniqueProcessId;
            string name = info->ImageName.Buffer != IntPtr.Zero && info->ImageName.Length > 0
                ? new string((char*)info->ImageName.Buffer, 0, info->ImageName.Length / 2)
                : pid == 0 ? "System Idle Process" : "System";

            result.Add(new RawProcessSample(
                Pid: pid,
                ParentPid: (int)(long)info->InheritedFromUniqueProcessId,
                Name: name,
                CreateTime: info->CreateTime,
                CpuTime: info->KernelTime + info->UserTime,
                WorkingSet: (long)(ulong)info->WorkingSetSize,
                PrivateWorkingSet: info->WorkingSetPrivateSize,
                ThreadCount: (int)info->NumberOfThreads,
                HandleCount: (int)info->HandleCount,
                ReadBytes: (ulong)info->ReadTransferCount,
                WriteBytes: (ulong)info->WriteTransferCount,
                OtherBytes: (ulong)info->OtherTransferCount));

            if (info->NextEntryOffset == 0) break;
            offset += info->NextEntryOffset;
        }
        return result;
    }

    public static HashSet<int> ToolhelpPids()
    {
        var set = new HashSet<int>();
        IntPtr snap = Kernel32.CreateToolhelp32Snapshot(Kernel32.TH32CS_SNAPPROCESS, 0);
        if (snap == Kernel32.INVALID_HANDLE_VALUE || snap == IntPtr.Zero) return set;
        try
        {
            var entry = new Kernel32.PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<Kernel32.PROCESSENTRY32W>() };
            if (!Kernel32.Process32FirstW(snap, ref entry)) return set;
            do { set.Add((int)entry.th32ProcessID); } while (Kernel32.Process32NextW(snap, ref entry));
        }
        finally
        {
            Kernel32.CloseHandle(snap);
        }
        return set;
    }

    public static HashSet<int> EnumProcessesPids()
    {
        int capacity = 2048;
        while (true)
        {
            var ids = new uint[capacity];
            if (!Kernel32.K32EnumProcesses(ids, ids.Length * sizeof(uint), out int bytes)) return new HashSet<int>();
            int count = bytes / sizeof(uint);
            if (count < capacity) return ids.Take(count).Select(i => (int)i).ToHashSet();
            capacity *= 2;
        }
    }

    /// <summary>
    /// Tries OpenProcess on every PID (multiples of 4). Processes that unlink themselves from the
    /// kernel's process list usually still answer here. Terminated processes that are only kept
    /// alive by someone's open handle ("zombies") are skipped, otherwise they would look hidden.
    /// </summary>
    public static HashSet<int> BruteForcePids(int maxPid, CancellationToken cancel = default)
    {
        var set = new HashSet<int>();
        for (int pid = 4; pid <= maxPid; pid += 4)
        {
            if ((pid & 0xFFF) == 0) cancel.ThrowIfCancellationRequested();

            IntPtr h = Kernel32.OpenProcess(Kernel32.PROCESS_QUERY_LIMITED_INFORMATION | Kernel32.SYNCHRONIZE, false, pid);
            if (h == IntPtr.Zero)
            {
                // Access denied means the PID exists but is protected. Since we cannot confirm it is
                // still running, it is only counted if the primary list also has it (handled by the detector).
                continue;
            }
            try
            {
                if (Kernel32.GetProcessId(h) != pid) continue;
                if (Kernel32.WaitForSingleObject(h, 0) != Kernel32.WAIT_TIMEOUT) continue; // already exited
                set.Add(pid);
            }
            finally
            {
                Kernel32.CloseHandle(h);
            }
        }
        return set;
    }

    public static bool IsStillRunning(int pid)
    {
        IntPtr h = Kernel32.OpenProcess(Kernel32.SYNCHRONIZE | Kernel32.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return false;
        try { return Kernel32.WaitForSingleObject(h, 0) == Kernel32.WAIT_TIMEOUT; }
        finally { Kernel32.CloseHandle(h); }
    }

    /// <summary>Kills a process. Returns an error message, or null on success.</summary>
    public static string? Terminate(int pid)
    {
        IntPtr h = Kernel32.OpenProcess(Kernel32.PROCESS_TERMINATE, false, pid);
        if (h == IntPtr.Zero)
        {
            int err = Marshal.GetLastWin32Error();
            return err == Kernel32.ERROR_ACCESS_DENIED
                ? "Erişim reddedildi. Bu işlem Windows tarafından korunuyor olabilir."
                : $"İşlem açılamadı (hata {err}).";
        }
        try
        {
            return Kernel32.TerminateProcess(h, 1) ? null : $"Sonlandırılamadı (hata {Marshal.GetLastWin32Error()}).";
        }
        finally
        {
            Kernel32.CloseHandle(h);
        }
    }
}
