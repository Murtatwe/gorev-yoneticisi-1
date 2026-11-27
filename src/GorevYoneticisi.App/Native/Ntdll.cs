using System.Runtime.InteropServices;

namespace GorevYoneticisi.App.Native;

internal static class Ntdll
{
    public const int SystemProcessInformation = 5;
    public const int SystemProcessorPerformanceInformation = 8;
    public const int SystemProcessIdInformation = 88;
    public const int ProcessCommandLineInformation = 60;

    public const uint STATUS_SUCCESS = 0;
    public const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
    public const uint STATUS_BUFFER_TOO_SMALL = 0xC0000023;
    public const uint STATUS_BUFFER_OVERFLOW = 0x80000005;

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    /// <summary>SYSTEM_PROCESS_INFORMATION (layout from the Windows SDK / phnt).</summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_PROCESS_INFORMATION
    {
        public uint NextEntryOffset;
        public uint NumberOfThreads;
        public long WorkingSetPrivateSize;
        public uint HardFaultCount;
        public uint NumberOfThreadsHighWatermark;
        public ulong CycleTime;
        public long CreateTime;
        public long UserTime;
        public long KernelTime;
        public UNICODE_STRING ImageName;
        public int BasePriority;
        public IntPtr UniqueProcessId;
        public IntPtr InheritedFromUniqueProcessId;
        public uint HandleCount;
        public uint SessionId;
        public UIntPtr UniqueProcessKey;
        public UIntPtr PeakVirtualSize;
        public UIntPtr VirtualSize;
        public uint PageFaultCount;
        public UIntPtr PeakWorkingSetSize;
        public UIntPtr WorkingSetSize;
        public UIntPtr QuotaPeakPagedPoolUsage;
        public UIntPtr QuotaPagedPoolUsage;
        public UIntPtr QuotaPeakNonPagedPoolUsage;
        public UIntPtr QuotaNonPagedPoolUsage;
        public UIntPtr PagefileUsage;
        public UIntPtr PeakPagefileUsage;
        public UIntPtr PrivatePageCount;
        public long ReadOperationCount;
        public long WriteOperationCount;
        public long OtherOperationCount;
        public long ReadTransferCount;
        public long WriteTransferCount;
        public long OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
    {
        public long IdleTime;
        public long KernelTime;
        public long UserTime;
        public long DpcTime;
        public long InterruptTime;
        public uint InterruptCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SYSTEM_PROCESS_ID_INFORMATION
    {
        public IntPtr ProcessId;
        public UNICODE_STRING ImageName;
    }

    [DllImport("ntdll.dll")]
    public static extern uint NtQuerySystemInformation(int infoClass, IntPtr buffer, int length, out int returnLength);

    [DllImport("ntdll.dll")]
    public static extern uint NtQueryInformationProcess(IntPtr process, int infoClass, IntPtr buffer, int length, out int returnLength);
}
