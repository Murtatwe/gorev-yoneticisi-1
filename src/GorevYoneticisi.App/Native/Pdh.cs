using System.Runtime.InteropServices;

namespace GorevYoneticisi.App.Native;

internal static class Pdh
{
    public const uint ERROR_SUCCESS = 0;
    public const uint PDH_MORE_DATA = 0x800007D2;
    public const uint PDH_FMT_DOUBLE = 0x00000200;
    public const uint PDH_FMT_LARGE = 0x00000400;
    public const uint PDH_FMT_NOCAP100 = 0x00008000;
    public const uint PDH_CSTATUS_VALID_DATA = 0x0;
    public const uint PDH_CSTATUS_NEW_DATA = 0x1;

    [StructLayout(LayoutKind.Explicit)]
    public struct PDH_FMT_COUNTERVALUE
    {
        [FieldOffset(0)] public uint CStatus;
        [FieldOffset(8)] public double DoubleValue;
        [FieldOffset(8)] public long LargeValue;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PDH_FMT_COUNTERVALUE_ITEM_W
    {
        public IntPtr szName;
        public PDH_FMT_COUNTERVALUE FmtValue;
    }

    [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
    public static extern uint PdhOpenQueryW(string? dataSource, IntPtr userData, out IntPtr query);

    /// <summary>English counter names work on every Windows display language (e.g. Turkish).</summary>
    [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
    public static extern uint PdhAddEnglishCounterW(IntPtr query, string counterPath, IntPtr userData, out IntPtr counter);

    [DllImport("pdh.dll")]
    public static extern uint PdhCollectQueryData(IntPtr query);

    [DllImport("pdh.dll", CharSet = CharSet.Unicode)]
    public static extern uint PdhGetFormattedCounterArrayW(IntPtr counter, uint format, ref int bufferSize, out int itemCount, IntPtr buffer);

    [DllImport("pdh.dll")]
    public static extern uint PdhGetFormattedCounterValue(IntPtr counter, uint format, IntPtr type, out PDH_FMT_COUNTERVALUE value);

    [DllImport("pdh.dll")]
    public static extern uint PdhCloseQuery(IntPtr query);
}
