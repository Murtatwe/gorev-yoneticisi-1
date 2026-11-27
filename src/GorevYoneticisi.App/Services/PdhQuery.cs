using System.Runtime.InteropServices;
using GorevYoneticisi.App.Native;

namespace GorevYoneticisi.App.Services;

/// <summary>
/// Thin wrapper over a PDH query using English counter paths (works on Turkish Windows).
/// Rate counters need two collections before they return data.
/// </summary>
internal sealed class PdhQuery : IDisposable
{
    private IntPtr _query;
    private readonly Dictionary<string, IntPtr> _counters = new();

    public PdhQuery()
    {
        if (Pdh.PdhOpenQueryW(null, IntPtr.Zero, out _query) != Pdh.ERROR_SUCCESS) _query = IntPtr.Zero;
    }

    public bool IsOpen => _query != IntPtr.Zero;

    public bool TryAdd(string key, string englishPath)
    {
        if (_query == IntPtr.Zero) return false;
        if (Pdh.PdhAddEnglishCounterW(_query, englishPath, IntPtr.Zero, out var counter) != Pdh.ERROR_SUCCESS) return false;
        _counters[key] = counter;
        return true;
    }

    public bool Has(string key) => _counters.ContainsKey(key);

    public bool Collect() => _query != IntPtr.Zero && Pdh.PdhCollectQueryData(_query) == Pdh.ERROR_SUCCESS;

    public double? GetValue(string key)
    {
        if (!_counters.TryGetValue(key, out var counter)) return null;
        uint status = Pdh.PdhGetFormattedCounterValue(counter, Pdh.PDH_FMT_DOUBLE | Pdh.PDH_FMT_NOCAP100, IntPtr.Zero, out var value);
        if (status != Pdh.ERROR_SUCCESS) return null;
        if (value.CStatus != Pdh.PDH_CSTATUS_VALID_DATA && value.CStatus != Pdh.PDH_CSTATUS_NEW_DATA) return null;
        return value.DoubleValue;
    }

    public unsafe List<(string Instance, double Value)> GetArray(string key)
    {
        var result = new List<(string, double)>();
        if (!_counters.TryGetValue(key, out var counter)) return result;

        int size = 0;
        uint status = Pdh.PdhGetFormattedCounterArrayW(counter, Pdh.PDH_FMT_DOUBLE | Pdh.PDH_FMT_NOCAP100, ref size, out _, IntPtr.Zero);
        if (status != Pdh.PDH_MORE_DATA || size <= 0) return result;

        IntPtr buffer = Marshal.AllocHGlobal(size);
        try
        {
            status = Pdh.PdhGetFormattedCounterArrayW(counter, Pdh.PDH_FMT_DOUBLE | Pdh.PDH_FMT_NOCAP100, ref size, out int count, buffer);
            if (status != Pdh.ERROR_SUCCESS) return result;
            var items = (Pdh.PDH_FMT_COUNTERVALUE_ITEM_W*)buffer;
            for (int i = 0; i < count; i++)
            {
                var item = items[i];
                if (item.FmtValue.CStatus != Pdh.PDH_CSTATUS_VALID_DATA && item.FmtValue.CStatus != Pdh.PDH_CSTATUS_NEW_DATA) continue;
                string name = Marshal.PtrToStringUni(item.szName) ?? "";
                result.Add((name, item.FmtValue.DoubleValue));
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
        return result;
    }

    public void Dispose()
    {
        if (_query != IntPtr.Zero)
        {
            Pdh.PdhCloseQuery(_query);
            _query = IntPtr.Zero;
        }
        _counters.Clear();
    }
}
