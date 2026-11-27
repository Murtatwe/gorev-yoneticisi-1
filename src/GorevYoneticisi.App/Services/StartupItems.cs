using System.Management;
using System.Runtime.InteropServices;
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
/// Everything Windows starts automatically: Run keys, Startup folders, scheduled tasks (including ones hidden from
/// Task Scheduler), services, drivers, Winlogon, IFEO hijacks, WMI subscriptions and forced browser extensions.
/// Must be called from a background thread (it walks COM collections that can take seconds).
/// </summary>
internal sealed class StartupItems
{
    private readonly string _windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
    private readonly Dictionary<string, string> _noDeviceMap = new();
    private dynamic? _shell;

    public List<StartupEntry> Read()
    {
        var list = new List<StartupEntry>();
        try
        {
            Safe(() => ReadRunKeys(list));
            Safe(() => ReadStartupFolders(list));
            Safe(() => ReadWinlogon(list));
            Safe(() => ReadIfeo(list));
            Safe(() => ReadServices(list));
            Safe(() => ReadScheduledTasks(list));
            Safe(() => ReadHiddenScheduledTasks(list));
            Safe(() => ReadWmiSubscriptions(list));
            Safe(() => ReadBrowserPolicies(list));
        }
        finally
        {
            if (_shell is not null)
            {
                try { Marshal.FinalReleaseComObject(_shell); } catch { }
                _shell = null;
            }
        }
        return list;
    }

    private static void Safe(Action a)
    {
        try { a(); } catch (Exception ex) { App.Log(ex, "Başlangıç kaynağı okunamadı"); }
    }

    private string Normalize(string path) =>
        DevicePaths.NormalizeImagePath(path, _noDeviceMap, _windowsDir, Environment.ExpandEnvironmentVariables);

    private string? Resolve(string command)
    {
        string? target = CommandLine.ExtractTarget(Environment.ExpandEnvironmentVariables(command));
        if (string.IsNullOrEmpty(target)) return null;
        if (target.StartsWith("http", StringComparison.OrdinalIgnoreCase)) return target;
        return FindOnPath(Normalize(target));
    }

    /// <summary>Bare names (e.g. "rundll32.exe", "shell32.dll") are looked up the way Windows would.</summary>
    private string FindOnPath(string path)
    {
        if (Path.IsPathRooted(path)) return path;
        foreach (string dir in new[] { Path.Combine(_windowsDir, "System32"), _windowsDir, Path.Combine(_windowsDir, "System32", "wbem") })
        {
            foreach (string candidate in new[] { Path.Combine(dir, path), Path.Combine(dir, path + ".exe") })
            {
                if (File.Exists(candidate)) return candidate;
            }
        }
        return path;
    }

    private void Add(List<StartupEntry> list, string category, string location, string name, string command,
        bool enabled = true, string? extraReason = null, int extraScore = 0, string? overrideTarget = null, bool noTarget = false)
    {
        string? target = noTarget ? null : overrideTarget ?? Resolve(command);
        list.Add(new StartupEntry(category, location, name, command, target, enabled,
            extraReason is null ? Array.Empty<string>() : new[] { extraReason }, extraScore));
    }

    // ---------------------------------------------------------------- Run keys

    private void ReadRunKeys(List<StartupEntry> list)
    {
        var keys = new (RegistryKey Hive, string Path, string Label, string Approved)[]
        {
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"HKLM\...\Run", "Run"),
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", @"HKLM\...\RunOnce", ""),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", @"HKLM\WOW6432Node\...\Run", "Run32"),
            (Registry.LocalMachine, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", @"HKLM\WOW6432Node\...\RunOnce", ""),
            (Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", @"HKLM\...\Policies\Explorer\Run", ""),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", @"HKCU\...\Run", "Run"),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", @"HKCU\...\RunOnce", ""),
            (Registry.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", @"HKCU\...\Policies\Explorer\Run", ""),
        };

        foreach (var (hive, path, label, approved) in keys)
        {
            using var key = hive.OpenSubKey(path);
            if (key is null) continue;
            var disabled = approved.Length == 0 ? new HashSet<string>() : DisabledNames(hive, approved);
            foreach (string name in key.GetValueNames())
            {
                if (key.GetValue(name) is not string cmd || string.IsNullOrWhiteSpace(cmd)) continue;
                Add(list, "Kayıt Defteri (Run)", label, name.Length == 0 ? "(Varsayılan)" : name, cmd, enabled: !disabled.Contains(name));
            }
        }

        // Old-style per-user autostart values that still work.
        using (var win = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Windows"))
        {
            foreach (string value in new[] { "Load", "Run" })
            {
                if (win?.GetValue(value) is string cmd && !string.IsNullOrWhiteSpace(cmd))
                    Add(list, "Kayıt Defteri (Run)", $@"HKCU\...\Windows NT\CurrentVersion\Windows\{value}", value, cmd,
                        extraReason: "Eski ve nadir kullanılan bir otomatik başlatma yeri; zararlılar fark edilmemek için kullanır.", extraScore: 20);
            }
        }
    }

    /// <summary>
    /// Task Manager's "disable" switch stores per-hive state under StartupApproved; bit 0 of the first byte set = disabled.
    /// </summary>
    private static HashSet<string> DisabledNames(RegistryKey hive, string subKey)
    {
        var disabled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        using var k = hive.OpenSubKey($@"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\{subKey}");
        if (k is null) return disabled;
        foreach (var v in k.GetValueNames())
            if (k.GetValue(v) is byte[] b && b.Length > 0 && (b[0] & 1) == 1) disabled.Add(v);
        return disabled;
    }

    // ---------------------------------------------------------------- Startup folders

    private void ReadStartupFolders(List<StartupEntry> list)
    {
        foreach (var (folder, label, hive) in new[]
        {
            (Environment.GetFolderPath(Environment.SpecialFolder.Startup), "Kullanıcı Başlangıç klasörü", Registry.CurrentUser),
            (Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "Ortak Başlangıç klasörü", Registry.LocalMachine),
        })
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder)) continue;
            var disabled = DisabledNames(hive, "StartupFolder");
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
                        command = string.IsNullOrEmpty(args) ? $"\"{t}\"" : $"\"{t}\" {args}";
                        target = Resolve(command) ?? t;
                    }
                }
                Add(list, "Başlangıç klasörü", label, name, command, enabled: !disabled.Contains(name), overrideTarget: target);
            }
        }
    }

    private (string? Target, string? Args) ResolveShortcut(string lnk)
    {
        try
        {
            if (_shell is null)
            {
                var type = Type.GetTypeFromProgID("WScript.Shell");
                if (type is null) return (null, null);
                _shell = Activator.CreateInstance(type);
            }
            dynamic shortcut = _shell!.CreateShortcut(lnk);
            try
            {
                string target = shortcut.TargetPath;
                string args = shortcut.Arguments;
                return (string.IsNullOrEmpty(target) ? null : target, args);
            }
            finally
            {
                Marshal.FinalReleaseComObject(shortcut);
            }
        }
        catch
        {
            return (null, null);
        }
    }

    // ---------------------------------------------------------------- Winlogon / IFEO

    private void ReadWinlogon(List<StartupEntry> list)
    {
        const string path = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon";
        foreach (var (hive, label) in new[] { (Registry.LocalMachine, "HKLM"), (Registry.CurrentUser, "HKCU") })
        {
            using var key = hive.OpenSubKey(path);
            if (key is null) continue;

            if (key.GetValue("Shell") is string shell && !string.IsNullOrWhiteSpace(shell))
            {
                var parts = SplitList(shell);
                for (int i = 0; i < parts.Length; i++)
                {
                    string p = parts[i];
                    string? dir = Path.GetDirectoryName(p);
                    bool isExplorer = Path.GetFileName(p).Equals("explorer.exe", StringComparison.OrdinalIgnoreCase) &&
                                      (string.IsNullOrEmpty(dir) || dir.TrimEnd('\\').Equals(_windowsDir, StringComparison.OrdinalIgnoreCase));
                    bool normal = isExplorer && parts.Length == 1;
                    Add(list, "Winlogon", $@"{label}\...\Winlogon\Shell", i == 0 ? "Shell" : $"Shell (ek {i})", p,
                        extraReason: normal ? null : "Oturum açılışında Windows masaüstü (explorer.exe) yerine ya da onunla birlikte başka bir program çalıştırılıyor. Zararlıların sevdiği bir yöntemdir.",
                        extraScore: normal || isExplorer ? 0 : 70);
                }
            }

            if (hive == Registry.LocalMachine && key.GetValue("Userinit") is string userinit)
            {
                var parts = SplitList(userinit);
                for (int i = 0; i < parts.Length; i++)
                {
                    bool isUserinit = Path.GetFileName(parts[i]).Equals("userinit.exe", StringComparison.OrdinalIgnoreCase);
                    Add(list, "Winlogon", @"HKLM\...\Winlogon\Userinit", i == 0 ? "Userinit" : $"Userinit (ek {i})", parts[i],
                        extraReason: isUserinit ? null : "Oturum açılışında userinit.exe'ye ek olarak başka bir program çalıştırılıyor.",
                        extraScore: isUserinit ? 0 : 70);
                }
            }
        }
    }

    private static string[] SplitList(string value) =>
        value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private void ReadIfeo(List<StartupEntry> list)
    {
        foreach (string root in new[]
        {
            @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            @"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
        })
        {
            using var ifeo = Registry.LocalMachine.OpenSubKey(root);
            if (ifeo is null) continue;
            foreach (string exe in ifeo.GetSubKeyNames())
            {
                using var k = ifeo.OpenSubKey(exe);
                if (k?.GetValue("Debugger") is string debugger && !string.IsNullOrWhiteSpace(debugger))
                {
                    Add(list, "Program yönlendirme (IFEO)", $@"HKLM\...\Image File Execution Options\{exe}", exe, debugger,
                        extraReason: $"{exe} her açıldığında onun yerine bu program çalıştırılıyor. Bazı geliştirici araçları bunu kullanır, ama zararlıların sevdiği bir yöntemdir.",
                        extraScore: 50);
                }
            }
        }

        // GlobalFlag 0x200 + SilentProcessExit\<exe>\MonitorProcess runs a program whenever <exe> exits.
        using var spe = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit");
        if (spe is null) return;
        foreach (string exe in spe.GetSubKeyNames())
        {
            using var k = spe.OpenSubKey(exe);
            if (k?.GetValue("MonitorProcess") is string monitor && !string.IsNullOrWhiteSpace(monitor))
            {
                Add(list, "Program yönlendirme (IFEO)", $@"HKLM\...\SilentProcessExit\{exe}", $"{exe} kapanınca", monitor,
                    extraReason: $"{exe} her kapandığında bu program çalıştırılıyor. Nadiren meşrudur; gizli kalıcılık için kullanılır.",
                    extraScore: 50);
            }
        }
    }

    // ---------------------------------------------------------------- Services and drivers

    private void ReadServices(List<StartupEntry> list)
    {
        using var root = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
        if (root is null) return;
        foreach (string name in root.GetSubKeyNames())
        {
            using var k = root.OpenSubKey(name);
            if (k is null) continue;
            if (k.GetValue("Start") is not int start || start > 2) continue; // boot, system, automatic
            int type = k.GetValue("Type") is int t ? t : 0;
            bool driver = (type & 0x3) != 0;
            string? image = k.GetValue("ImagePath") as string;
            if (string.IsNullOrWhiteSpace(image))
            {
                if (!driver) continue;
                image = $@"System32\drivers\{name}.sys"; // Windows' default location for drivers without ImagePath
            }

            string display = k.GetValue("DisplayName") as string ?? name;
            if (display.StartsWith('@')) display = name; // resource reference like @%SystemRoot%\...dll,-100

            string? target = null;
            string? dll = k.GetValue("ServiceDll") as string;
            using (var p = k.OpenSubKey("Parameters"))
            {
                if (p?.GetValue("ServiceDll") is string pdll) dll = pdll;
            }
            if (!string.IsNullOrWhiteSpace(dll)) target = FindOnPath(Normalize(dll)); // a DLL path, not a command line

            Add(list, driver ? "Sürücü" : "Servis", $@"HKLM\...\Services\{name}", display, image, overrideTarget: target);
        }
    }

    // ---------------------------------------------------------------- Scheduled tasks

    private void ReadScheduledTasks(List<StartupEntry> list)
    {
        var type = Type.GetTypeFromProgID("Schedule.Service");
        if (type is null) return;
        dynamic service = Activator.CreateInstance(type)!;
        try
        {
            service.Connect();
            Walk(service.GetFolder("\\"), list, depth: 0);
        }
        finally
        {
            Marshal.FinalReleaseComObject(service);
        }
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
                        int actionType = (int)action.Type;
                        if (actionType == 0) // run a program
                        {
                            string exe = action.Path ?? "";
                            string args = action.Arguments ?? "";
                            if (string.IsNullOrWhiteSpace(exe)) continue;
                            string command = exe.Contains(' ') && !exe.StartsWith('"') ? $"\"{exe}\" {args}" : $"{exe} {args}";
                            Add(list, "Zamanlanmış görev", path, name, command.Trim(), enabled);
                        }
                        else if (actionType == 5) // COM handler: the DLL registered for the CLSID runs
                        {
                            string clsid = action.ClassId ?? "";
                            string? dll = ComServerFor(clsid);
                            Add(list, "Zamanlanmış görev (COM)", path, name, $"COM {clsid}", enabled,
                                overrideTarget: dll, noTarget: dll is null);
                        }
                    }
                }
                catch { /* skip unreadable task */ }
            }
            foreach (dynamic sub in folder.GetFolders(0)) Walk(sub, list, depth + 1);
        }
        catch { }
    }

    private string? ComServerFor(string clsid)
    {
        if (string.IsNullOrWhiteSpace(clsid)) return null;
        foreach (var hive in new[] { Registry.CurrentUser, Registry.LocalMachine })
        {
            using var k = hive.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}\InprocServer32") ?? hive.OpenSubKey($@"SOFTWARE\Classes\CLSID\{clsid}\LocalServer32");
            if (k?.GetValue(null) is string server && !string.IsNullOrWhiteSpace(server))
                return Resolve(server);
        }
        return null;
    }

    /// <summary>
    /// Tasks whose security descriptor ("SD") was deleted from the registry vanish from Task Scheduler but
    /// keep running (the "Tarrask" technique). Such entries are found by walking the TaskCache tree directly.
    /// </summary>
    private void ReadHiddenScheduledTasks(List<StartupEntry> list)
    {
        using var tree = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree");
        if (tree is null) return;
        WalkTree(tree, "", list, 0);
    }

    private void WalkTree(RegistryKey key, string path, List<StartupEntry> list, int depth)
    {
        if (depth > 16) return;
        foreach (string sub in key.GetSubKeyNames())
        {
            using var k = key.OpenSubKey(sub);
            if (k is null) continue;
            string taskPath = $@"{path}\{sub}";
            if (k.GetValue("Id") is string && k.GetValue("SD") is null)
            {
                Add(list, "Zamanlanmış görev (gizlenmiş)", $@"TaskCache\Tree{taskPath}", sub, taskPath, noTarget: true,
                    extraReason: "Bu zamanlanmış görev Görev Zamanlayıcı'dan gizlenmiş (güvenlik tanımlayıcısı silinmiş). Bu, bilinen bir zararlı yazılım hilesidir.",
                    extraScore: 70);
            }
            WalkTree(k, taskPath, list, depth + 1);
        }
    }

    // ---------------------------------------------------------------- WMI

    /// <summary>Permanent WMI event subscriptions that run a command or script (used by "fileless" malware and miners).</summary>
    private void ReadWmiSubscriptions(List<StartupEntry> list)
    {
        var scope = new ManagementScope(@"\\.\root\subscription");
        scope.Connect();

        using (var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM CommandLineEventConsumer")))
        {
            foreach (ManagementObject o in searcher.Get())
            {
                using (o)
                {
                    string name = o["Name"] as string ?? "(adsız)";
                    string cmd = (o["CommandLineTemplate"] as string) ?? (o["ExecutablePath"] as string) ?? "";
                    Add(list, "WMI olay aboneliği", @"root\subscription\CommandLineEventConsumer", name, cmd,
                        extraReason: "Windows Yönetim Araçları (WMI) bir olay olduğunda bu komutu çalıştırıyor. Meşru kullanımı çok nadirdir; dosyasız zararlıların tipik yöntemidir.",
                        extraScore: 60);
                }
            }
        }
        using (var searcher = new ManagementObjectSearcher(scope, new ObjectQuery("SELECT * FROM ActiveScriptEventConsumer")))
        {
            foreach (ManagementObject o in searcher.Get())
            {
                using (o)
                {
                    string name = o["Name"] as string ?? "(adsız)";
                    string script = (o["ScriptFileName"] as string) ?? "(gömülü betik)";
                    Add(list, "WMI olay aboneliği", @"root\subscription\ActiveScriptEventConsumer", name, script,
                        noTarget: (o["ScriptFileName"] as string) is null,
                        extraReason: "Windows Yönetim Araçları (WMI) bir olay olduğunda bir betik çalıştırıyor. Meşru kullanımı çok nadirdir.",
                        extraScore: 60);
                }
            }
        }
    }

    // ---------------------------------------------------------------- Browsers

    /// <summary>Extensions forced into browsers by policy ("Tarayıcınız kuruluşunuz tarafından yönetiliyor"): the most common adware persistence.</summary>
    private void ReadBrowserPolicies(List<StartupEntry> list)
    {
        var browsers = new (string Key, string Name)[]
        {
            (@"SOFTWARE\Policies\Google\Chrome", "Chrome"),
            (@"SOFTWARE\Policies\Microsoft\Edge", "Edge"),
            (@"SOFTWARE\Policies\BraveSoftware\Brave", "Brave"),
        };
        foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            foreach (var (keyPath, browser) in browsers)
            {
                using var key = hive.OpenSubKey($@"{keyPath}\ExtensionInstallForcelist");
                if (key is null) continue;
                foreach (string valueName in key.GetValueNames())
                {
                    if (key.GetValue(valueName) is not string value || string.IsNullOrWhiteSpace(value)) continue;
                    string id = value.Split(';')[0];
                    Add(list, "Tarayıcı eklentisi (zorunlu)", $@"{(hive == Registry.LocalMachine ? "HKLM" : "HKCU")}\{keyPath}\ExtensionInstallForcelist",
                        $"{browser}: {id}", value, noTarget: true,
                        extraReason: $"Bu eklenti {browser} tarayıcısına zorla yükleniyor ve kaldırılamıyor. Şirket bilgisayarı değilse genellikle reklam yazılımıdır.",
                        extraScore: 35);
                }
            }
        }
    }
}
