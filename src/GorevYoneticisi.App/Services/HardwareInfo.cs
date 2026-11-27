using Microsoft.Win32;
using GorevYoneticisi.App.Native;

namespace GorevYoneticisi.App.Services;

public sealed record GpuAdapterInfo(string Name, long DedicatedMemoryBytes);

/// <summary>Static hardware description, read once at startup.</summary>
public sealed record HardwareInfo(
    string CpuName,
    int LogicalProcessors,
    string CpuBaseSpeed,
    ulong TotalMemoryBytes,
    IReadOnlyList<GpuAdapterInfo> Gpus,
    string OsName)
{
    public static HardwareInfo Read()
    {
        string cpu = "Bilinmeyen işlemci";
        string speed = "";
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            cpu = (key?.GetValue("ProcessorNameString") as string)?.Trim() ?? cpu;
            if (key?.GetValue("~MHz") is int mhz) speed = $"{mhz / 1000.0:0.00} GHz".Replace('.', ',');
        }
        catch { /* registry unavailable */ }

        var mem = new Kernel32.MEMORYSTATUSEX { dwLength = (uint)System.Runtime.InteropServices.Marshal.SizeOf<Kernel32.MEMORYSTATUSEX>() };
        Kernel32.GlobalMemoryStatusEx(ref mem);

        return new HardwareInfo(cpu, SystemCpuCount(), speed, mem.ullTotalPhys, ReadGpus(), ReadOsName());
    }

    /// <summary>All logical processors in all groups (Environment.ProcessorCount honours affinity and can be lower).</summary>
    public static int SystemCpuCount()
    {
        try
        {
            int n = Kernel32.GetActiveProcessorCount(Kernel32.ALL_PROCESSOR_GROUPS);
            if (n > 0) return n;
        }
        catch { }
        return Environment.ProcessorCount;
    }

    private static List<GpuAdapterInfo> ReadGpus()
    {
        var list = new List<GpuAdapterInfo>();
        try
        {
            using var cls = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}");
            if (cls is null) return list;
            foreach (var sub in cls.GetSubKeyNames().Where(n => n.Length == 4 && n.All(char.IsDigit)))
            {
                using var k = cls.OpenSubKey(sub);
                if (k?.GetValue("DriverDesc") is not string name) continue;
                long memory = k.GetValue("HardwareInformation.qwMemorySize") switch
                {
                    long l => l,
                    byte[] b when b.Length >= 8 => BitConverter.ToInt64(b, 0),
                    _ => k.GetValue("HardwareInformation.MemorySize") switch
                    {
                        int i => (uint)i,
                        byte[] b when b.Length >= 4 => BitConverter.ToUInt32(b, 0),
                        _ => 0,
                    },
                };
                if (list.Any(g => g.Name == name)) continue;
                list.Add(new GpuAdapterInfo(name, memory));
            }
        }
        catch { }
        // Real GPUs first, the basic display driver last.
        return list.OrderBy(g => g.Name.Contains("Microsoft", StringComparison.OrdinalIgnoreCase)).ThenByDescending(g => g.DedicatedMemoryBytes).ToList();
    }

    private static string ReadOsName()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            string product = k?.GetValue("ProductName") as string ?? "Windows";
            string display = k?.GetValue("DisplayVersion") as string ?? "";
            string build = k?.GetValue("CurrentBuild") as string ?? "";
            // ProductName still says "Windows 10" on Windows 11.
            if (int.TryParse(build, out int b) && b >= 22000) product = product.Replace("Windows 10", "Windows 11");
            return $"{product} {display} (derleme {build})".Trim();
        }
        catch
        {
            return Environment.OSVersion.VersionString;
        }
    }
}
