using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text;
using GorevYoneticisi.App.Native;
using GorevYoneticisi.Core.Security;

namespace GorevYoneticisi.App.Services;

public sealed record SignatureInfo(SignatureStatus Status, string? Signer, bool CheckFailed = false, bool StorePackage = false)
{
    public static readonly SignatureInfo Pending = new(SignatureStatus.Unknown, null);
    public static readonly SignatureInfo Failed = new(SignatureStatus.Unknown, null, CheckFailed: true);

    public string Display => Status switch
    {
        SignatureStatus.Signed => Signer ?? "İmzalı",
        SignatureStatus.Unsigned when StorePackage => "Store paketi (paket imzalı)",
        SignatureStatus.Unsigned => "İmzasız",
        SignatureStatus.Invalid => "Geçersiz imza",
        SignatureStatus.Untrusted => "Güvenilmeyen imza",
        SignatureStatus.Expired => (Signer ?? "İmzalı") + " (süresi dolmuş)",
        _ => CheckFailed ? "Denetlenemedi" : "…",
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
    private const int ERROR_NOT_FOUND = 1168;

    /// <summary>Unsigned files bigger than this outside Windows/Program Files are not hashed for a catalog lookup.</summary>
    private const long CatalogHashLimit = 64L * 1024 * 1024;

    private enum CatalogResult { NotInCatalog, LookupFailed, Found }

    public static SignatureInfo Verify(string path)
    {
        try
        {
            int embedded = VerifyFile(path, out string? signer);
            if (embedded == 0) return new SignatureInfo(SignatureStatus.Signed, signer);

            var embeddedStatus = Map(embedded);
            bool noEmbedded = embeddedStatus == SignatureStatus.Unsigned;

            // Windows' own files are mostly signed via catalogs. Also try the catalog when the embedded
            // signature fails for chain reasons: the catalog signature may still be valid.
            if (noEmbedded || embeddedStatus is SignatureStatus.Untrusted or SignatureStatus.Expired)
            {
                if (noEmbedded && !WorthCatalogLookup(path)) return new SignatureInfo(SignatureStatus.Unsigned, null);

                var (result, hr, catSigner) = VerifyCatalog(path);
                if (result == CatalogResult.Found && hr == 0) return new SignatureInfo(SignatureStatus.Signed, catSigner);
                if (noEmbedded)
                {
                    return result switch
                    {
                        CatalogResult.NotInCatalog => new SignatureInfo(SignatureStatus.Unsigned, null),
                        CatalogResult.LookupFailed => SignatureInfo.Failed, // e.g. CryptSvc stopped: do not call it unsigned
                        _ => new SignatureInfo(Map(hr), catSigner),
                    };
                }
            }
            return embeddedStatus == SignatureStatus.Unknown ? SignatureInfo.Failed : new SignatureInfo(embeddedStatus, signer);
        }
        catch
        {
            return SignatureInfo.Failed;
        }
    }

    private static bool WorthCatalogLookup(string path)
    {
        try
        {
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            if (path.StartsWith(win, StringComparison.OrdinalIgnoreCase) || path.StartsWith(pf, StringComparison.OrdinalIgnoreCase)) return true;
            return new FileInfo(path).Length <= CatalogHashLimit;
        }
        catch
        {
            return true;
        }
    }

    private static SignatureStatus Map(int hr) => hr switch
    {
        0 => SignatureStatus.Signed,
        TRUST_E_NOSIGNATURE or TRUST_E_SUBJECT_FORM_UNKNOWN or TRUST_E_PROVIDER_UNKNOWN => SignatureStatus.Unsigned,
        TRUST_E_BAD_DIGEST => SignatureStatus.Invalid,
        CERT_E_EXPIRED => SignatureStatus.Expired,
        CERT_E_UNTRUSTEDROOT or CERT_E_CHAINING or CERT_E_REVOKED or
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

    private static (CatalogResult Result, int Hr, string? Signer) VerifyCatalog(string path)
    {
        Microsoft.Win32.SafeHandles.SafeFileHandle file;
        try
        {
            file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
        }
        catch
        {
            return (CatalogResult.LookupFailed, 0, null);
        }

        using (file)
        {
            IntPtr hFile = file.DangerousGetHandle();
            bool anyContext = false;
            int lastHr = 0;
            string? lastSigner = null;
            bool foundAny = false;

            foreach (string? algorithm in new[] { "SHA256", null })
            {
                if (!WinTrust.CryptCATAdminAcquireContext2(out IntPtr admin, IntPtr.Zero, algorithm, IntPtr.Zero, 0)) continue;
                anyContext = true;
                try
                {
                    uint hashSize = 0;
                    WinTrust.CryptCATAdminCalcHashFromFileHandle2(admin, hFile, ref hashSize, null, 0);
                    if (hashSize == 0) continue;
                    var hash = new byte[hashSize];
                    if (!WinTrust.CryptCATAdminCalcHashFromFileHandle2(admin, hFile, ref hashSize, hash, 0)) continue;

                    // A file can be listed in several catalogs; try each until one verifies.
                    IntPtr prev = IntPtr.Zero;
                    while (true)
                    {
                        IntPtr catInfo = WinTrust.CryptCATAdminEnumCatalogFromHash(admin, hash, hashSize, 0, ref prev);
                        if (catInfo == IntPtr.Zero)
                        {
                            int err = Marshal.GetLastWin32Error();
                            if (!foundAny && err != ERROR_NOT_FOUND && err != 0) return (CatalogResult.LookupFailed, 0, null);
                            break;
                        }
                        // EnumCatalogFromHash releases the previous context itself when it is passed back in.
                        prev = catInfo;
                        var ci = new WinTrust.CATALOG_INFO { cbStruct = (uint)Marshal.SizeOf<WinTrust.CATALOG_INFO>() };
                        if (!WinTrust.CryptCATCatalogInfoFromContext(catInfo, ref ci, 0)) continue;
                        foundAny = true;
                        lastHr = RunCatalog(path, hFile, admin, hash, ci.wszCatalogFile, out lastSigner);
                        if (lastHr == 0)
                        {
                            WinTrust.CryptCATAdminReleaseCatalogContext(admin, catInfo, 0);
                            return (CatalogResult.Found, 0, lastSigner);
                        }
                    }
                    // The last context was passed back into EnumCatalogFromHash, which released it.
                }
                finally
                {
                    WinTrust.CryptCATAdminReleaseContext(admin, 0);
                }
                if (foundAny) break; // found in SHA256 catalogs but failed: SHA1 catalogs won't help
            }

            if (!anyContext) return (CatalogResult.LookupFailed, 0, null);
            return foundAny ? (CatalogResult.Found, lastHr, lastSigner) : (CatalogResult.NotInCatalog, 0, null);
        }
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
/// and queues the file. Running processes are checked before startup entries.
/// </summary>
internal sealed class SignatureCache : IDisposable
{
    private readonly ConcurrentDictionary<string, (string Stamp, SignatureInfo Info, long CheckedAt)> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _queued = new(StringComparer.OrdinalIgnoreCase);
    private readonly BlockingCollection<string> _high = new();
    private readonly BlockingCollection<string> _low = new();
    private readonly CancellationTokenSource _cts = new();
    private readonly Thread[] _workers;
    private static readonly long RecheckTicks = TimeSpan.FromSeconds(30).Ticks;
    private static readonly long RetryFailedTicks = TimeSpan.FromMinutes(5).Ticks;
    private long _lastNotify;
    private int _notifyScheduled;

    /// <summary>Raised (debounced, at most twice a second) when new results are available. Called on a worker thread.</summary>
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

    public SignatureInfo Get(string? path, bool highPriority = true)
    {
        if (string.IsNullOrEmpty(path) || !Path.IsPathFullyQualified(path)) return SignatureInfo.Pending;
        long now = DateTime.UtcNow.Ticks;
        if (_cache.TryGetValue(path, out var entry))
        {
            long ttl = entry.Info.CheckFailed ? RetryFailedTicks : RecheckTicks;
            if (now - entry.CheckedAt < ttl) return entry.Info;
            if (!entry.Info.CheckFailed && entry.Stamp == Stamp(path))
            {
                _cache[path] = entry with { CheckedAt = now };
                return entry.Info;
            }
        }
        if (_queued.TryAdd(path, 0)) (highPriority ? _high : _low).Add(path);
        return entry.Info ?? SignatureInfo.Pending;
    }

    private static bool IsStorePackage(string path) =>
        path.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase) ||
        path.Contains(@"\SystemApps\", StringComparison.OrdinalIgnoreCase);

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
        var queues = new[] { _high, _low };
        while (!_cts.IsCancellationRequested)
        {
            string path;
            try
            {
                BlockingCollection<string>.TakeFromAny(queues, out path!, _cts.Token);
            }
            catch (OperationCanceledException) { return; }
            catch (ObjectDisposedException) { return; }
            catch (ArgumentException) { return; } // collections completed

            try
            {
                string stamp = Stamp(path);
                SignatureInfo info = stamp switch
                {
                    "missing" => SignatureInfo.Pending,
                    "error" => SignatureInfo.Failed,
                    _ => SignatureVerifier.Verify(path),
                };
                if (info.Status == SignatureStatus.Unsigned && IsStorePackage(path)) info = info with { StorePackage = true };
                _cache[path] = (stamp, info, DateTime.UtcNow.Ticks);
            }
            catch (Exception ex)
            {
                App.Log(ex, "İmza denetimi");
            }
            finally
            {
                _queued.TryRemove(path, out _);
            }
            Notify();
        }
    }

    private void Notify()
    {
        long now = Environment.TickCount64;
        if (now - Interlocked.Read(ref _lastNotify) >= 500)
        {
            Interlocked.Exchange(ref _lastNotify, now);
            Raise();
        }
        else if (Interlocked.Exchange(ref _notifyScheduled, 1) == 0)
        {
            // Make sure the last batch is reported even if no further results arrive.
            _ = Task.Delay(600).ContinueWith(_ =>
            {
                Interlocked.Exchange(ref _notifyScheduled, 0);
                Interlocked.Exchange(ref _lastNotify, Environment.TickCount64);
                Raise();
            }, TaskScheduler.Default);
        }
    }

    private void Raise()
    {
        try
        {
            Updated?.Invoke();
        }
        catch (Exception ex)
        {
            App.Log(ex, "İmza bildirimi");
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _high.CompleteAdding();
        _low.CompleteAdding();
    }
}
