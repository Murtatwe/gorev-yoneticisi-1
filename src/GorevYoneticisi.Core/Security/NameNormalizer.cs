using System.Text;

namespace GorevYoneticisi.Core.Security;

/// <summary>
/// Defeats file-name tricks: invisible/bidirectional characters (RTLO), trailing spaces or dots
/// (which Windows ignores), and look-alike letters from other alphabets (Cyrillic "ѕ" for "s").
/// </summary>
public static class NameNormalizer
{
    private static readonly Dictionary<char, char> Confusables = new()
    {
        // Cyrillic
        ['а'] = 'a', ['е'] = 'e', ['о'] = 'o', ['р'] = 'p', ['с'] = 'c', ['у'] = 'y', ['х'] = 'x',
        ['ѕ'] = 's', ['і'] = 'i', ['ј'] = 'j', ['һ'] = 'h', ['ԁ'] = 'd', ['ӏ'] = 'l', ['ԛ'] = 'q',
        ['ԝ'] = 'w', ['в'] = 'b', ['к'] = 'k', ['м'] = 'm', ['н'] = 'h', ['т'] = 't', ['ь'] = 'b',
        // Greek
        ['ο'] = 'o', ['α'] = 'a', ['ε'] = 'e', ['ι'] = 'i', ['κ'] = 'k', ['ν'] = 'v', ['ρ'] = 'p',
        ['τ'] = 't', ['υ'] = 'u', ['χ'] = 'x', ['β'] = 'b', ['η'] = 'n',
        // Turkish dotless i looks like i in most fonts
        ['ı'] = 'i',
    };

    public static bool IsInvisible(char c) =>
        c is >= '​' and <= '‏'
          or >= '‪' and <= '‮'
          or >= '⁦' and <= '⁩'
          or '﻿' or '­' or '⁠';

    private static bool IsForeignScript(char c) =>
        c is >= 'Ͱ' and <= 'Ͽ'   // Greek
          or >= 'Ѐ' and <= 'ԯ';  // Cyrillic

    /// <summary>Canonical lower-case form used for comparing names.</summary>
    public static string Skeleton(string raw)
    {
        if (string.IsNullOrEmpty(raw)) return "";
        var sb = new StringBuilder(raw.Length);
        foreach (char c in raw.Normalize(NormalizationForm.FormKC))
        {
            if (IsInvisible(c)) continue;
            char lower = char.ToLowerInvariant(c);
            sb.Append(Confusables.TryGetValue(lower, out char mapped) ? mapped : lower);
        }
        return sb.ToString().TrimEnd(' ', '.', '\t');
    }

    /// <summary>
    /// Even more aggressive form for look-alike comparison only (0→o, 1→l, rn→m, vv→w).
    /// </summary>
    public static string LookalikeKey(string raw) =>
        Skeleton(raw).Replace('0', 'o').Replace('1', 'l').Replace("rn", "m").Replace("vv", "w");

    public static bool HasMisleadingCharacters(string raw)
    {
        if (string.IsNullOrEmpty(raw)) return false;
        if (raw.Any(IsInvisible)) return true;
        if (raw.Length > 0 && (raw[^1] == ' ' || raw[^1] == '.')) return true;
        bool foreign = raw.Any(IsForeignScript);
        bool latin = raw.Any(c => c is >= 'a' and <= 'z' or >= 'A' and <= 'Z');
        return foreign && latin;
    }
}
