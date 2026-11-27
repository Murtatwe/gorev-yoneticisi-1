using System.Text.RegularExpressions;

namespace GorevYoneticisi.Core;

/// <summary>Finds the file a Windows command line (Run key, service, scheduled task) actually executes.</summary>
public static partial class CommandLine
{
    private static readonly string[] ExecutableExtensions = { ".exe", ".com", ".bat", ".cmd", ".scr", ".pif", ".sys" };

    [GeneratedRegex(@"\.[A-Za-z0-9]{1,4}$", RegexOptions.CultureInvariant)]
    private static partial Regex AnyExtension();

    /// <summary>
    /// For script/DLL hosts (rundll32, regsvr32, powershell -File, wscript, cmd /c, mshta) the script or DLL is
    /// returned, because that is what deserves inspection, not the Windows host. Otherwise the program itself.
    /// </summary>
    public static string? ExtractTarget(string? command)
    {
        if (string.IsNullOrWhiteSpace(command)) return null;
        string cmd = command.Trim();
        var (program, rest) = SplitProgram(cmd);
        if (string.IsNullOrEmpty(program)) return null;

        string host = program.Replace('/', '\\').Split('\\')[^1].ToLowerInvariant();
        if (host.EndsWith(".exe", StringComparison.Ordinal)) host = host[..^4];

        string? inner = host switch
        {
            "rundll32" => FirstPathSkippingSwitches(rest, switchPrefix: null),
            "regsvr32" => FirstPathSkippingSwitches(rest, switchPrefix: "/"),
            "wscript" or "cscript" => FirstPathSkippingSwitches(rest, switchPrefix: "/"),
            "mshta" => FirstPathSkippingSwitches(rest, switchPrefix: "-"),
            "powershell" or "pwsh" => PathAfterFlag(rest, "-file", "-f", "/file"),
            "cmd" => ScriptAfterFlag(rest, "/c", "/k"),
            _ => null,
        };
        return string.IsNullOrEmpty(inner) ? program : inner;
    }

    /// <summary>Splits off the program the way CreateProcess does for unquoted paths with spaces.</summary>
    private static (string Program, string Remainder) SplitProgram(string cmd)
    {
        if (cmd.StartsWith('"'))
        {
            int end = cmd.IndexOf('"', 1);
            return end < 0 ? (cmd.Trim('"'), "") : (cmd[1..end], cmd[(end + 1)..]);
        }
        for (int i = 0; i <= cmd.Length; i++)
        {
            if (i < cmd.Length && cmd[i] != ' ') continue;
            string candidate = cmd[..i];
            if (ExecutableExtensions.Any(e => candidate.EndsWith(e, StringComparison.OrdinalIgnoreCase)))
                return (candidate, i < cmd.Length ? cmd[(i + 1)..] : "");
        }
        int space = cmd.IndexOf(' ');
        return space < 0 ? (cmd, "") : (cmd[..space], cmd[(space + 1)..]);
    }

    private static List<(string Text, int Start)> Tokens(string s)
    {
        var list = new List<(string, int)>();
        int i = 0;
        while (i < s.Length)
        {
            while (i < s.Length && char.IsWhiteSpace(s[i])) i++;
            if (i >= s.Length) break;
            int start = i;
            if (s[i] == '"')
            {
                int end = s.IndexOf('"', i + 1);
                if (end < 0) end = s.Length;
                list.Add((s[(i + 1)..end], start));
                i = end + 1;
            }
            else
            {
                while (i < s.Length && !char.IsWhiteSpace(s[i])) i++;
                list.Add((s[start..i], start));
            }
        }
        return list;
    }

    /// <summary>Reads a path starting at <paramref name="start"/>, allowing unquoted spaces until something that looks like a file extension.</summary>
    private static string PathAt(string s, int start)
    {
        if (start < s.Length && s[start] == '"')
        {
            int end = s.IndexOf('"', start + 1);
            return end < 0 ? s[(start + 1)..] : s[(start + 1)..end];
        }
        for (int j = start; j <= s.Length; j++)
        {
            if (j < s.Length && s[j] != ' ' && s[j] != ',') continue;
            string candidate = s[start..j];
            if (AnyExtension().IsMatch(candidate)) return candidate;
        }
        int stop = s.IndexOfAny(new[] { ' ', ',' }, start);
        return stop < 0 ? s[start..] : s[start..stop];
    }

    private static string? FirstPathSkippingSwitches(string rest, string? switchPrefix)
    {
        foreach (var (text, start) in Tokens(rest))
        {
            if (switchPrefix is not null && text.StartsWith(switchPrefix, StringComparison.Ordinal)) continue;
            string path = PathAt(rest, start);
            return path.Length == 0 ? null : path;
        }
        return null;
    }

    private static string? PathAfterFlag(string rest, params string[] flags)
    {
        var tokens = Tokens(rest);
        for (int i = 0; i < tokens.Count - 1; i++)
        {
            if (flags.Contains(tokens[i].Text, StringComparer.OrdinalIgnoreCase))
                return PathAt(rest, tokens[i + 1].Start);
        }
        return null;
    }

    private static string? ScriptAfterFlag(string rest, params string[] flags)
    {
        string? path = PathAfterFlag(rest, flags);
        if (path is null) return null;
        return ExecutableExtensions.Any(e => path.EndsWith(e, StringComparison.OrdinalIgnoreCase)) ? path : null;
    }
}
