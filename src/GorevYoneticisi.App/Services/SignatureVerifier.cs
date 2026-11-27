using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using GorevYoneticisi.App.Native;
using GorevYoneticisi.Core.Security;

namespace GorevYoneticisi.App.Services;

public sealed record SignatureInfo(SignatureStatus Status, string? Signer)
{
    public static readonly SignatureInfo Pending = new(SignatureStatus.Unknown, null);

    public string Display => Status switch
    {
        SignatureStatus.Signed => Signer ?? "İmzalı",
        SignatureStatus.Unsigned => "İmzasız",
        SignatureStatus.Invalid => "Geçersiz imza!",
        SignatureStatus.Untrusted => "Güvenilmeyen imza",
        _ => "…",
    };
}

/// <summary>Authenticode verification (embedded signature first, then Windows catalog signatures). No network access.</summary>
internal static class SignatureVerifier
{
    private const int TRUST_E_NOSIGNATURE = unchecked((int)0x800B0100);
    private const int TRUST_E_SUBJECT_FORM_UNKNOWN = unchecked((int)0x800B0003);
    private const int TRUST_E_PROVIDER_UNKNOWN = unchecked((int)0x800B0001);
    private const int TRUST_E_BAD_DIGEST = unchecked((int)0x80096010);
    private const int CERT_E_UNTRUSTEDROOT = unchecked((int)0x800B0109);
    private const int CERT_E_CHAINING = unchecked((int)0x800B010A);
    private const int CERT_E_REVOKED = unchecked((int)0x800B010C);
    private const int CERT_E_EXPIRED = unchecked((int)0x800B0101);
    private const int CERT_E_UNTRUSTEDTESTROOT = unchecked((int)0x800B010D);
    private const int TRUST_E_EXPLICIT_DISTRUST = unchecked((int)0x800B0111);
    private const int CRYPT_E_FILE_ERROR = unchecked((int)0x80092003);

    public static SignatureInfo Verify(string path)
    {
        try
        {
            int embedded = VerifyFile(path, out string? signer);
            if (embedded == 0) return new SignatureInfo(SignatureStatus.Signed, signer);

            if (embedded is TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN)
            {
                int? catalog = VerifyCatalog(path, out string? catSigner);
                if (catalog == 0) return new SignatureInfo(SignatureStatus.Signed, catSigner);
                if (catalog is null) return new SignatureInfo(SignatureStatus.Unsigned, null);
                return new SignatureInfo(Map(catalog.Value), catSigner);
            }
            return new SignatureInfo(Map(embedded), signer);
        }
        catch
        {
            return SignatureInfo.Pending;
        }
    }

    private static SignatureStatus Map(int hr) => hr switch
    {
        0 => SignatureStatus.Signed,
        TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN => SignatureStatus.Unsigned,
        TRUST_E_BAD_DIGEST => SignatureStatus.Invalid,
        CERT_E_UNTRUSTEDROOT or CERT_E_CHAINING or CERT_E_REVOKED or CERT_E_EXPIRED or
            CERT_E_UNTRUSTEDTESTROOT or TRUST_E_EXPLICIT_DISTRUST => SignatureStatus.Untrusted,
        _ => SignatureStatus.Unknown, // file errors, access denied, policy errors: do not guess
    };

    private static int VerifyFile(string path, out string? signer)
    {
        signer = null;
        IntPtr pathPtr = Marshal.StringToHGlobalUni(path);
        var fileInfo = new WinTrust.WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrust.WINTRUST_FILE_INFO>(),
            pcwszFilePath = pathPtr,
        };
        IntPtr infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrust.WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, infoPtr, false);
            return Run(WinTrust.WTD_CHOICE_FILE, infoPtr, out signer);
        }
        finally
        {
            Marshal.FreeHGlobal(infoPtr);
            Marshal.FreeHGlobal(pathPtr);
        }
    }

    /// <returns>WinVerifyTrust result for the catalog, or null when no catalog contains the file.</returns>
    private static int? VerifyCatalog(string path, out string? signer)
    {
        signer = null;
        using var file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        IntPtr hFile = file.DangerousGetHandle();

        foreach (string? algorithm in new[] { "SHA256", null })
        {
            if (!WinTrust.CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) continue;
            try
            {
                uint hashSize = 0;
                WinTrust.CryptCATAdminCalcHashFromFileHandle2(admin, hFile, ref hashSize, null, 0);
                if (hashSize == 0) continue;
                var hash = new byte[hashSize];
                if (!WinTrust.CryptCATAdminCalcHashFromFileHandle2(admin, hFile, ref hashSize, hash, 0)) continue;

                IntPtr prev = IntPtr.Zero;
                IntPtr catInfo = WinTrust.CryptCATAdminEnumCatalogFromHash(admin, hash, hashSize, 0, ref prev);
                if (catInfo == IntPtr.Zero) continue;
                try
                {
                    var ci = new WinTrust.CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<WinTrust.CATALOG_INFO>() };
                    if (!WinTrust.CryptCATCatalogInfoFromContext(catInfo, ref ci, 0)) continue;
                    return RunCatalog(path, hFile, admin, hash, ci.wszCatalogFile, out signer);
                }
                finally
                {
                    WinTrust.CryptCATAdminReleaseCatalogContext(admin, catInfo, 0);
                }
            }
            finally
            {
                WinTrust.CryptCATAdminReleaseContext(admin, 0);
            }
        }
        return null;
    }

    private static int RunCatalog(string path, IntPtr hFile, IntPtr admin, byte[] hash, string catalogFile, out string? signer)
    {
        string memberTag = Convert.ToHexString(hash);
        IntPtr catPtr = Marshal.StringToHGlobalUni(catalogFile);
        IntPtr tagPtr = Marshal.StringToHGlobalUni(memberTag);
        IntPtr pathPtr = Marshal.StringToHGlobalUni(path);
        IntPtr hashPtr = Marshal.AllocHGlobal(hash.Length);
        IntPtr infoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrust.WINTRUST_CATALOG_INFO>());
        try
        {
            Marshal.Copy(hash, 0, hashPtr, hash.Length);
            var info = new WinTrust.WINTRUST_CATALOG_INFO
            {
                cbStruct = (uint)Marshal.SizeOf<WinTrust.WINTRUST_CATALOG_INFO>(),
                pcwszCatalogFilePath = catPtr,
                pcwszMemberTag = tagPtr,
                pcwszMemberFilePath = pathPtr,
                hMemberFile = hFile,
                pbCalculatedFileHash = hashPtr,
                cbCalculatedFileHash = (uint)hash.Length,
                hCatAdmin = admin,
            };
            Marshal.StructureToPtr(info, infoPtr, false);
            return Run(WinTrust.WTD_CHOICE_CATALOG, infoPtr, out signer);
        }
        finally
        {
            Marshal.FreeHGlobal(infoPtr);
            Marshal.FreeHGlobal(hashPtr);
            Marshal.FreeHGlobal(pathPtr);
            Marshal.FreeHGlobal(tagPtr);
            Marshal.FreeHGlobal(catPtr);
        }
    }

    private static int Run(uint unionChoice, IntPtr info, out string? signer)
    {
        signer = null;
        var guid = WinTrust.WINTRUST_ACTION_GENERIC_VERIFY_V2;
        var data = new WinTrust.WINTRUST_DATA
        {
            cbStruct = (uint)Marshal.SizeOf<WinTrust.WINTRUST_DATA>(),
            dwUIChoice = WinTrust.WTD_UI_NONE,
            fdwRevocationChecks = WinTrust.WTD_REVOKE_NONE,
            dwUnionChoice = unionChoice,
            pInfo = info,
            dwStateAction = WinTrust.WTD_STATEACTION_VERIFY,
            dwProvFlags = WinTrust.WTD_REVOCATION_CHECK_NONE | WinTrust.WTD_CACHE_ONLY_URL_RETRIEVAL,
        };

        int result = WinTrust.WinVerifyTrust(IntPtr.Zero, ref guid, ref data);
        try
        {
            if (data.hWVTStateData != IntPtr.Zero) signer = ReadSigner(data.hWVTStateData);
        }
        catch
        {
            signer = null;
        }
        finally
        {
            data.dwStateAction = WinTrust.WTD_STATEACTION_CLOSE;
            WinTrust.WinVerifyTrust(IntPtr.Zero, ref guid, ref data);
        }
        return result;
    }

    private static string? ReadSigner(IntPtr state)
    {
        IntPtr prov = WinTrust.WTHelperProvDataFromStateData(state);
        if (prov == IntPtr.Zero) return null;
        IntPtr sgnr = WinTrust.WTHelperGetProvSignerFromChain(prov, 0, false, 0);
        if (sgnr == IntPtr.Zero) return null;

        // CRYPT_PROVIDER_SGNR: DWORD cbStruct; FILETIME sftVerifyAsOf; DWORD csCertChain; CRYPT_PROVIDER_CERT* pasCertChain
        int chainCount = Marshal.ReadInt32(sgnr, 12);
        if (chainCount <= 0) return null;
        IntPtr chain = Marshal.ReadIntPtr(sgnr, 16);
        if (chain == IntPtr.Zero) return null;
        // CRYPT_PROVIDER_CERT: DWORD cbStruct; PCCERT_CONTEXT pCert (pointer-aligned)
        IntPtr cert = Marshal.ReadIntPtr(chain, IntPtr.Size);
        if (cert == IntPtr.Zero) return null;

        var sb = new StringBuilder(256);
        int len = WinTrust.CertGetNameStringW(cert, WinTrust.CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, IntPtr.Zero, sb, sb.Capacity);
        return len > 1 ? sb.ToString() : null;
    }
}

/// <summary>
/// Background, cached signature checks. Results are keyed by path + size + last write time, so a file that
/// changes is checked again. <see cref="Get"/> never blocks: it returns <see cref="SignatureInfo.Pending"/>
/// and queues the file.
/// </summary>
internal sealed class SignatureCache : IDisposable
{
    private readonly ConcurrentDictionary<string, (string Stamp, SignatureInfo Info, long CheckedAt)> _cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly long RecheckTicks = TimeSpan.FromSeconds(30).Ticks;
    private readonly ConcurrentDictionary<string, byte> _queued = new(StringComparer.OrdinalIgnoreCase);
    private readonly BlockingCollection<string> _queue = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Thread[] _workers;

    public event Action? Updated;

    public SignatureCache(int workers = 2)
    {
        _workers = Enumerable.Range(0, workers).Select(i => new Thread(Work)
        {
            IsBackground = true,
            Name = $"İmza denetimi {i + 1}",
            Priority = ThreadPriority.BelowNormal,
        }).ToArray();
        foreach (var w in _workers) w.Start();
    }

    public SignatureInfo Get(string? path)
    {
        if (string.IsNullOrEmpty(path) || !Path.IsPathFullyQualified(path)) return SignatureInfo.Pending;
        long now = DateTime.UtcNow.Ticks;
        if (_cache.TryGetValue(path, out var entry))
        {
            if (now - entry.CheckedAt < RecheckTicks) return entry.Info;
            if (entry.Stamp == Stamp(path))
            {
                _cache[path] = entry with { CheckedAt = now };
                return entry.Info;
            }
        }
        if (_queued.TryAdd(path, 0)) _queue.Add(path);
        return entry.Info ?? SignatureInfo.Pending;
    }

    private static string Stamp(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            return fi.Exists ? $"{fi.Length}:{fi.LastWriteTimeUtc.Ticks}" : "missing";
        }
        catch
        {
            return "error";
        }
    }

    private void Work()
    {
        try
        {
            foreach (string path in _queue.GetConsumingEnumerable(_cts.Token))
            {
                string stamp = Stamp(path);
                var info = stamp is "missing" or "error" ? SignatureInfo.Pending : SignatureVerifier.Verify(path);
                _cache[path] = (stamp, info, DateTime.UtcNow.Ticks);
                _queued.TryRemove(path, out _);
                if (_queue.Count == 0) Updated?.Invoke();
            }
        }
        catch (OperationCanceledException) { }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _queue.CompleteAdding();
    }
}
