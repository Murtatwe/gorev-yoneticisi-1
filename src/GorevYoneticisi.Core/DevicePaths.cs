namespace GorevYoneticisi.Core;

public static class DevicePaths
{
    /// <summary>
    /// Converts NT-style paths (\Device\HarddiskVolume3\..., \??\C:\..., \SystemRoot\..., UNC/MUP) to normal DOS paths.
    /// </summary>
    /// <param name="deviceMap">Device name (e.g. \Device\HarddiskVolume3) to drive (e.g. C:).</param>
    public static string ToDosPath(string path, IReadOnlyDictionary<string, string> deviceMap, string? windowsDirectory = null)
    {
        if (string.IsNullOrEmpty(path)) return path;

        if (path.StartsWith(@"\\.\", StringComparison.Ordinal))
            path = path[4..];
        else if (path.StartsWith(@"\??\UNC\", StringComparison.OrdinalIgnoreCase) || path.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
            return @"\\" + path[8..];
        else if (path.StartsWith(@"\??\", StringComparison.Ordinal) || path.StartsWith(@"\\?\", StringComparison.Ordinal))
            path = path[4..];

        if (path.StartsWith(@"\Device\Mup\", StringComparison.OrdinalIgnoreCase))
            return @"\\" + path[@"\Device\Mup\".Length..];

        if (path.StartsWith(@"\Device\LanmanRedirector\", StringComparison.OrdinalIgnoreCase))
        {
            string rest = path[@"\Device\LanmanRedirector\".Length..];
            if (rest.StartsWith(';'))
            {
                int slash = rest.IndexOf('\\');
                rest = slash < 0 ? "" : rest[(slash + 1)..];
            }
            return @"\\" + rest;
        }

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

    /// <summary>
    /// Normalizes paths as stored in the registry (services, Run keys): surrounding quotes, %VARIABLES%,
    /// paths relative to the Windows folder (System32\drivers\x.sys) and rooted paths without a drive.
    /// </summary>
    public static string NormalizeImagePath(string raw, IReadOnlyDictionary<string, string> deviceMap, string windowsDirectory, Func<string, string> expandEnvironment)
    {
        if (string.IsNullOrWhiteSpace(raw)) return raw;
        string s = raw.Trim().Trim('"');
        if (s.Contains('%')) s = expandEnvironment(s);
        s = ToDosPath(s, deviceMap, windowsDirectory);

        string winRoot = windowsDirectory.TrimEnd('\\');
        if (s.StartsWith(@"system32\", StringComparison.OrdinalIgnoreCase) || s.StartsWith(@"syswow64\", StringComparison.OrdinalIgnoreCase))
            return winRoot + @"\" + s;
        if (s.StartsWith('\\') && !s.StartsWith(@"\\", StringComparison.Ordinal) && winRoot.Length >= 2)
            return winRoot[..2] + s;
        return s;
    }
}
