namespace GorevYoneticisi.Core;

public static class DevicePaths
{
    /// <summary>
    /// Converts NT-style paths (\Device\HarddiskVolume3\..., \??\C:\..., \SystemRoot\...) to normal DOS paths.
    /// </summary>
    /// <param name="deviceMap">Device name (e.g. \Device\HarddiskVolume3) to drive (e.g. C:).</param>
    public static string ToDosPath(string path, IReadOnlyDictionary<string, string> deviceMap, string? windowsDirectory = null)
    {
        if (string.IsNullOrEmpty(path)) return path;

        if (path.StartsWith(@"\??\", StringComparison.Ordinal) || path.StartsWith(@"\\?\", StringComparison.Ordinal))
            path = path[4..];

        if (windowsDirectory is not null && path.StartsWith(@"\SystemRoot\", StringComparison.OrdinalIgnoreCase))
            return windowsDirectory.TrimEnd('\\') + path[@"\SystemRoot".Length..];

        foreach (var (device, drive) in deviceMap.OrderByDescending(kv => kv.Key.Length))
        {
            if (path.StartsWith(device, StringComparison.OrdinalIgnoreCase) &&
                (path.Length == device.Length || path[device.Length] == '\\'))
            {
                return drive + path[device.Length..];
            }
        }
        return path;
    }
}
