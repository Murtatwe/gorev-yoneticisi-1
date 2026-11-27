using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using GorevYoneticisi.App.Services;
using GorevYoneticisi.App.ViewModels;

namespace GorevYoneticisi.App;

/// <summary>
/// Automated end-to-end check used by CI on a real Windows machine: starts the real UI, visits every page,
/// saves a screenshot of each and writes a JSON report. Run with: GorevYoneticisi.exe --smoke-test &lt;folder&gt;
/// </summary>
internal static class SmokeTest
{
    public static async void Run(Window window, MainViewModel vm, MonitorService monitor, string outDir)
    {
        var report = new Dictionary<string, object?>();
        var errors = new List<string>();
        Directory.CreateDirectory(outDir);
        int snapshots = 0;
        MonitorSnapshot? last = null;
        monitor.SnapshotReady += s => { Interlocked.Increment(ref snapshots); last = s; };

        try
        {
            window.Width = 1400;
            window.Height = 900;
            await Delay(6000);

            foreach (var page in vm.Pages)
            {
                vm.SelectedPage = page;
                await Delay(page.Page == vm.Startup ? 12000 : page.Page == vm.Security ? 8000 : 3000);
                try
                {
                    Save(window, Path.Combine(outDir, $"{vm.Pages.ToList().IndexOf(page) + 1}-{Slug(page.Title)}.png"));
                }
                catch (Exception ex)
                {
                    errors.Add($"Ekran görüntüsü ({page.Title}): {ex.Message}");
                }
            }

            var scan = await monitor.RunSecurityScanAsync();

            report["snapshots"] = snapshots;
            report["monitorError"] = monitor.LastError;
            report["debugPrivilege"] = monitor.DebugPrivilege;
            report["hardware"] = monitor.Hardware;
            if (last is not null)
            {
                report["totals"] = last.Totals;
                report["processCount"] = last.Processes.Count;
                report["processesWithPath"] = last.Processes.Count(p => p.Path is not null);
                report["signatureStates"] = last.Processes.GroupBy(p => p.Signature.Display.StartsWith("…") ? "bekliyor" : p.Signature.Status.ToString())
                    .ToDictionary(g => g.Key, g => g.Count());
                report["riskLevels"] = last.Processes.GroupBy(p => p.Risk.Level.ToString()).ToDictionary(g => g.Key, g => g.Count());
                report["riskyProcesses"] = last.Processes.Where(p => p.Risk.Level >= Core.Security.RiskLevel.Medium)
                    .Select(p => new { p.Name, p.Path, Level = p.Risk.Level.ToString(), p.Risk.Score, p.Risk.Reasons, Signature = p.Signature.Display }).ToList();
                report["topCpu"] = last.Processes.OrderByDescending(p => p.CpuPercent).Take(5).Select(p => new { p.Name, p.CpuPercent }).ToList();
                report["gpuProcesses"] = last.Processes.Where(p => p.GpuPercent > 0 || p.GpuMemory > 0).Select(p => new { p.Name, p.GpuPercent, p.GpuMemory }).ToList();
            }
            if (scan is not null)
            {
                report["securityScan"] = new
                {
                    scan.Duration.TotalMilliseconds,
                    scan.PrimaryCount,
                    scan.BruteForceCount,
                    scan.Result.PrimaryAvailable,
                    FailedMethods = scan.Result.FailedMethods.Select(m => m.ToString()),
                    Findings = scan.Items.Select(i => new { i.Name, i.Path, Kind = i.Finding.Kind.ToString(), i.Finding.Pid }),
                };
            }
            report["startupItems"] = vm.Startup.Rows.Count;
            report["startupByCategory"] = vm.Startup.Rows.GroupBy(r => r.Category).ToDictionary(g => g.Key, g => g.Count());
            report["startupRisky"] = vm.Startup.Rows.Where(r => r.Risk >= Core.Security.RiskLevel.Medium)
                .Select(r => new { r.Name, r.Category, r.Target, Level = r.Risk.ToString(), r.RiskScore, r.Reasons, r.Signature }).ToList();
            report["networkRows"] = vm.Network.Rows.Count;
        }
        catch (Exception ex)
        {
            errors.Add(ex.ToString());
        }

        string log = File.Exists(App.LogPath) ? File.ReadAllText(App.LogPath) : "";
        report["log"] = log;
        report["errors"] = errors;

        try
        {
            File.WriteAllText(Path.Combine(outDir, "rapor.json"),
                JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }),
                Encoding.UTF8);
        }
        catch (Exception ex)
        {
            File.WriteAllText(Path.Combine(outDir, "rapor-hata.txt"), ex.ToString());
        }

        bool failed = errors.Count > 0 || log.Length > 0 || snapshots < 3 || (last?.Processes.Count ?? 0) < 10;
        Application.Current.Shutdown(failed ? 2 : 0);
    }

    private static Task Delay(int ms)
    {
        var tcs = new TaskCompletionSource();
        var timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(ms) };
        timer.Tick += (_, _) => { timer.Stop(); tcs.SetResult(); };
        timer.Start();
        return tcs.Task;
    }

    private static void Save(Window window, string path)
    {
        var content = (FrameworkElement)window.Content;
        int w = (int)Math.Max(1, content.ActualWidth), h = (int)Math.Max(1, content.ActualHeight);
        var bmp = new RenderTargetBitmap(w, h, 96, 96, PixelFormats.Pbgra32);
        // Paint the theme background first; Mica is composited by Windows and not captured.
        var visual = new DrawingVisual();
        using (var dc = visual.RenderOpen())
        {
            var bg = Application.Current.TryFindResource("ApplicationBackgroundBrush") as Brush ?? Brushes.Black;
            dc.DrawRectangle(bg, null, new Rect(0, 0, w, h));
        }
        bmp.Render(visual);
        bmp.Render(content);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(bmp));
        using var fs = File.Create(path);
        encoder.Save(fs);
    }

    private static string Slug(string s) => new string(s.Select(c => char.IsLetterOrDigit(c) ? c : '-').ToArray()).ToLowerInvariant();
}
