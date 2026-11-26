using System.Text.RegularExpressions;

namespace GorevYoneticisi.Core;

public static partial class CommandLine
{
    [GeneratedRegex(@"^(.+?\.(?:exe|com|bat|cmd|scr|pif|dll|vbs|js|ps1))(?=\s|,|$)", RegexOptions.IgnoreCase)]
    private static partial Regex UnquotedExecutable();

    private static readonly string[] Hosts = { "rundll32.exe", "rundll32" };

    /// <summary>
    /// Extracts the file a command line actually runs. For rundll32 the DLL is returned,
    /// because the DLL is what deserves inspection, not the Windows host.
    /// </summary>
    public static string? ExtractTarget(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        string cmd = command.Trim();
        var (first, rest) = SplitFirst(cmd);
        if (first is null) return null;

        string fileName = first.Replace('/', '\\').Split('\\')[^1];
        if (Hosts.Contains(fileName, StringComparer.OrdinalIgnoreCase) && !string.IsNullOrWhiteSpace(rest))
        {
            string r = rest.TrimStart();
            if (r.StartsWith('"'))
            {
                int end = r.IndexOf('"', 1);
                if (end > 1) return r[1..end];
            }
            int stop = r.IndexOfAny(new[] { ',', ' ' });
            string dll = stop < 0 ? r : r[..stop];
            if (dll.Length > 0) return dll;
        }
        return first;
    }

    private static (string? First, string Remainder) SplitFirst(string cmd)
    {
        if (cmd.StartsWith('"'))
        {
            int end = cmd.IndexOf('"', 1);
            if (end < 0) return (cmd.Trim('"'), "");
            return (cmd[1..end], cmd[(end + 1)..]);
        }
        var m = UnquotedExecutable().Match(cmd);
        if (m.Success) return (m.Groups[1].Value, cmd[m.Groups[1].Length..]);
        int space = cmd.IndexOf(' ');
        return space < 0 ? (cmd, "") : (cmd[..space], cmd[(space + 1)..]);
    }
}
