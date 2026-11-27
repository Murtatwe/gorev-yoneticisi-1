using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace GorevYoneticisi.App.Ui;

/// <summary>Small (16x16) file icons via the shell, cached per path. Must be used on the UI thread.</summary>
public static class IconCache
{
    private static readonly Dictionary<string, ImageSource?> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static ImageSource? _default;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEINFOW
    {
        public IntPtr hIcon;
        public int iIcon;
        public uint dwAttributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szDisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)] public string szTypeName;
    }

    private const uint SHGFI_ICON = 0x100;
    private const uint SHGFI_SMALLICON = 0x1;
    private const uint SHGFI_USEFILEATTRIBUTES = 0x10;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SHGetFileInfoW(string path, uint attributes, ref SHFILEINFOW info, uint size, uint flags);

    [DllImport("user32.dll")]
    private static extern bool DestroyIcon(IntPtr icon);

    public static ImageSource? Get(string? path)
    {
        if (string.IsNullOrEmpty(path)) return Default();
        if (Cache.TryGetValue(path, out var cached)) return cached;
        var icon = Load(path, 0, SHGFI_ICON | SHGFI_SMALLICON) ?? Default();
        if (Cache.Count > 2000) Cache.Clear();
        Cache[path] = icon;
        return icon;
    }

    private static readonly Dictionary<string, List<Action<ImageSource?>>> Pending = new(StringComparer.OrdinalIgnoreCase);
    private static readonly Queue<string> Order = new();
    private static bool _pumping;

    /// <summary>
    /// Non-blocking variant: returns the cached icon, or the generic one right away and calls
    /// <paramref name="loaded"/> later (when the UI is idle) with the real icon.
    /// </summary>
    public static ImageSource? GetOrQueue(string? path, Action<ImageSource?> loaded)
    {
        if (string.IsNullOrEmpty(path)) return Default();
        if (Cache.TryGetValue(path, out var cached)) return cached;
        if (!Pending.TryGetValue(path, out var callbacks))
        {
            callbacks = new List<Action<ImageSource?>>();
            Pending[path] = callbacks;
            Order.Enqueue(path);
        }
        callbacks.Add(loaded);
        if (!_pumping)
        {
            _pumping = true;
            Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, Pump);
        }
        return Default();
    }

    private static void Pump()
    {
        // A few icons per idle slot keeps the UI responsive even with hundreds of new rows.
        for (int i = 0; i < 12 && Order.Count > 0; i++)
        {
            string path = Order.Dequeue();
            var icon = Get(path);
            if (Pending.Remove(path, out var callbacks))
                foreach (var cb in callbacks) cb(icon);
        }
        if (Order.Count > 0) Dispatcher.CurrentDispatcher.BeginInvoke(DispatcherPriority.ApplicationIdle, Pump);
        else _pumping = false;
    }

    private static ImageSource? Default() =>
        _default ??= Load("x.exe", FILE_ATTRIBUTE_NORMAL, SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES);

    private static ImageSource? Load(string path, uint attributes, uint flags)
    {
        try
        {
            var info = new SHFILEINFOW();
            SHGetFileInfoW(path, attributes, ref info, (uint)Marshal.SizeOf<SHFILEINFOW>(), flags);
            if (info.hIcon == IntPtr.Zero) return null;
            try
            {
                var source = Imaging.CreateBitmapSourceFromHIcon(info.hIcon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                source.Freeze();
                return source;
            }
            finally
            {
                DestroyIcon(info.hIcon);
            }
        }
        catch
        {
            return null;
        }
    }
}
