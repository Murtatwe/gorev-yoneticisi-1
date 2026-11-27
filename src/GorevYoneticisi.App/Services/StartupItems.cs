using Microsoft.Win32;
using GorevYoneticisi.Core;

namespace GorevYoneticisi.App.Services;

public sealed record StartupEntry(
    string Category,
    string Location,
    string Name,
    string Command,
    string? TargetPath,
    bool Enabled,
    IReadOnlyList<string> ExtraReasons,
    int ExtraScore);

/// <summary>
/// Everything Windows starts automatically: Run keys, Startup folders, scheduled tasks, services, drivers,
/// Winlogon and Image File Execution Options hijacks.
/// </summary>
internal sealed class StartupItems
{
    private readonly string _windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private readonly Dictionary<string, string> _noDeviceMap = new();

    public List<StartupEntry> Read()
    {
        var list = new List<StartupEntry>();
        Safe(() => ReadRunKeys(list));
        Safe(() => ReadStartupFolders(list));
        Safe(() => ReadWinlogon(list));
        Safe(() => ReadIfeo(list));
        Safe(() => ReadServices(list));
        Safe(() => ReadScheduledTasks(list));
        return list;
    }

    private static void Safe(Action a)
    {
        try { a(); } catch { /* one broken source must not hide the others */ }
    }

    private string? Resolve(string command)
    {
        string? target = CommandLine.ExtractTarget(command);
        if (string.IsNullOrEmpty(target)) return null;
        if (target.StartsWith("http", StringComparison.OrdinalIgnoreCase)) return target;
        string path = DevicePaths.NormalizeImagePath(target, _noDeviceMap, _windowsDir, Environment.ExpandEnvironmentVariables);

        if (!Path.IsPathRooted(path))
        {
            // Bare names (e.g. "rundll32.exe", "shell32.dll") are looked up the way Windows would.
            foreach (string dir in new[] { Path.Combine(_windowsDir, "System32"), _windowsDir })
            {
                foreach (string candidate in new[] { Path.Combine(dir, path), Path.Combine(dir, path + ".exe") })
                {
                    if (File.Exists(candidate)) return candidate;
                }
            }
        }
        return path;
    }

    private void Add(List<StartupEntry> list, string category, string location, string name, string command,
        bool enabled = true, string? extraReason = null, int extraScore = 0, string? overrideTarget = null)
    {
        list.Add(new StartupEntry(category, location, name, command, overrideTarget ?? Resolve(command), enabled,
            extraReason is null ? Array.Empty<string>() : new[] { extraReason }, extraScore));
    }

    private void ReadRunKeys(List<StartupEntry> list)
    {
        var keys = new (RegistryKey Hive, string Path, string Label)[]
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"HKLM\...\Run"),
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", @"HKLM\...\RunOnce"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", @"HKLM\WOW6432Node\...\Run"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", @"HKLM\WOW6432Node\...\RunOnce"),
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", @"HKLM\...\Policies\Explorer\Run"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"HKCU\...\Run"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", @"HKCU\...\RunOnce"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", @"HKCU\...\Policies\Explorer\Run"),
        };

        // Task Manager's "disable" switch stores state here; first byte 0x02/0x06 = enabled, 0x03 = disabled.
        var disabled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (hive, approved) in new[]
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run32"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run"),
        })
        {
            using var k = hive.OpenSubKey(approved);
            if (k is null) continue;
            foreach (var v in k.GetValueNames())
                if (k.GetValue(v) is byte[] b && b.Length > 0 && (b[0] & 1) == 1) disabled.Add(v);
        }

        foreach (var (hive, path, label) in keys)
        {
            using var key = hive.OpenSubKey(path);
            if (key is null) continue;
            foreach (string name in key.GetValueNames())
            {
                if (key.GetValue(name) is not string cmd || string.IsNullOrWhiteSpace(cmd)) continue;
                Add(list, "Kayıt Defteri (Run)", label, name.Length == 0 ? "(Varsayılan)" : name, cmd, enabled: !disabled.Contains(name));
            }
        }
    }

    private void ReadStartupFolders(List<StartupEntry> list)
    {
        foreach (var (folder, label) in new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Kullanıcı Başlangıç klasörü"),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Ortak Başlangıç klasörü"),
        })
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) continue;
            foreach (string file in Directory.GetFiles(folder))
            {
                string name = Path.GetFileName(file);
                if (name.Equals("desktop.ini", StringComparison.OrdinalIgnoreCase)) continue;
                string? target = file;
                string command = file;
                if (file.EndsWith(".lnk", StringComparison.OrdinalIgnoreCase))
                {
                    var (t, args) = ResolveShortcut(file);
                    if (t is not null)
                    {
                        target = t;
                        command = string.IsNullOrEmpty(args) ? $"\"{t}\"" : $"\"{t}\" {args}";
                        string? inner = Resolve(command);
                        if (inner is not null) target = inner;
                    }
                }
                Add(list, "Başlangıç klasörü", label, name, command, overrideTarget: target);
            }
        }
    }

    private static (string? Target, string? Args) ResolveShortcut(string lnk)
    {
        try
        {
            var type = Type.GetTypeFromProgID("WScript.Shell");
            if (type is null) return (null, null);
            dynamic shell = Activator.CreateInstance(type)!;
            dynamic shortcut = shell.CreateShortcut(lnk);
            string target = shortcut.TargetPath;
            string args = shortcut.Arguments;
            return (string.IsNullOrEmpty(target) ? null : target, args);
        }
        catch
        {
            return (null, null);
        }
    }

    private void ReadWinlogon(List<StartupEntry> list)
    {
        const string path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        using var key = Registry.LocalMachine.OpenSubKey(path);
        if (key is null) return;

        if (key.GetValue("Shell") is string shell)
        {
            bool normal = shell.Trim().Equals("explorer.exe", StringComparison.OrdinalIgnoreCase);
            Add(list, "Winlogon", @"HKLM\...\Winlogon\Shell", "Shell", shell,
                extraReason: normal ? null : "Windows masaüstü (explorer.exe) yerine başka bir program ayarlanmış. Zararlılar oturum açılışında çalışmak için bunu yapar.",
                extraScore: normal ? 0 : 70);
        }
        if (key.GetValue("Userinit") is string userinit)
        {
            var parts = userinit.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            bool normal = parts.Length == 1 && Path.GetFileName(parts[0]).Equals("userinit.exe", StringComparison.OrdinalIgnoreCase);
            Add(list, "Winlogon", @"HKLM\...\Winlogon\Userinit", "Userinit", userinit,
                extraReason: normal ? null : "Oturum açılışında userinit.exe'ye ek olarak başka bir program çalıştırılıyor.",
                extraScore: normal ? 0 : 70,
                overrideTarget: parts.Length > 1 ? Resolve(parts[^1]) : null);
        }
    }

    private void ReadIfeo(List<StartupEntry> list)
    {
        const string path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";
        using var root = Registry.LocalMachine.OpenSubKey(path);
        if (root is null) return;
        foreach (string exe in root.GetSubKeyNames())
        {
            using var k = root.OpenSubKey(exe);
            if (k?.GetValue("Debugger") is not string debugger || string.IsNullOrWhiteSpace(debugger)) continue;
            Add(list, "Program yönlendirme (IFEO)", $@"HKLM\...\Image File Execution Options\{exe}", exe, debugger,
                extraReason: $"{exe} her açıldığında onun yerine bu program çalıştırılıyor. Bazı geliştirici araçları bunu kullanır, ama zararlıların sevdiği bir yöntemdir.",
                extraScore: 50);
        }
    }

    private void ReadServices(List<StartupEntry> list)
    {
        using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (root is null) return;
        foreach (string name in root.GetSubKeyNames())
        {
            using var k = root.OpenSubKey(name);
            if (k is null) continue;
            if (k.GetValue("Start") is not int start || start > 2) continue; // boot, system, automatic
            if (k.GetValue("ImagePath") is not string image || string.IsNullOrWhiteSpace(image)) continue;
            int type = k.GetValue("Type") is int t ? t : 0;
            bool driver = (type & 0x3) != 0;

            string display = k.GetValue("DisplayName") as string ?? name;
            if (display.StartsWith('@')) display = name; // resource reference like @%SystemRoot%\...dll,-100

            string? target = null;
            using (var p = k.OpenSubKey("Parameters"))
            {
                if (p?.GetValue("ServiceDll") is string dll) target = Resolve(dll);
            }
            Add(list, driver ? "Sürücü" : "Servis", $@"HKLM\...\Services\{name}", display, image, overrideTarget: target);
        }
    }

    private void ReadScheduledTasks(List<StartupEntry> list)
    {
        var type = Type.GetTypeFromProgID("Schedule.Service");
        if (type is null) return;
        dynamic service = Activator.CreateInstance(type)!;
        service.Connect();
        Walk(service.GetFolder("\\"), list, depth: 0);
    }

    private void Walk(dynamic folder, List<StartupEntry> list, int depth)
    {
        if (depth > 16) return;
        try
        {
            foreach (dynamic task in folder.GetTasks(1)) // 1 = include hidden tasks
            {
                try
                {
                    string name = task.Name;
                    string path = task.Path;
                    bool enabled = task.Enabled;
                    foreach (dynamic action in task.Definition.Actions)
                    {
                        if ((int)action.Type != 0) continue; // 0 = run a program
                        string exe = action.Path ?? "";
                        string args = action.Arguments ?? "";
                        if (string.IsNullOrWhiteSpace(exe)) continue;
                        string command = exe.Contains(' ') && !exe.StartsWith('"') ? $"\"{exe}\" {args}" : $"{exe} {args}";
                        Add(list, "Zamanlanmış görev", path, name, command.Trim(), enabled);
                    }
                }
                catch { /* skip unreadable task */ }
            }
            foreach (dynamic sub in folder.GetFolders(0)) Walk(sub, list, depth + 1);
        }
        catch { }
    }
}
