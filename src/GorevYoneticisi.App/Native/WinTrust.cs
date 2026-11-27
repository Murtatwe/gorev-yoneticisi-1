using System.Runtime.InteropServices;
using System.Text;

namespace GorevYoneticisi.App.Native;

internal static class WinTrust
{
    public static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public const uint WTD_UI_NONE = 2;
    public const uint WTD_REVOKE_NONE = 0;
    public const uint WTD_CHOICE_FILE = 1;
    public const uint WTD_CHOICE_CATALOG = 2;
    public const uint WTD_STATEACTION_VERIFY = 1;
    public const uint WTD_STATEACTION_CLOSE = 2;
    public const uint WTD_REVOCATION_CHECK_NONE = 0x10;
    public const uint WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000;

    public const uint CERT_NAME_SIMPLE_DISPLAY_TYPE = 4;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WINTRUST_FILE_INFO
    {
        public uint cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WINTRUST_CATALOG_INFO
    {
        public uint cbStruct;
        public uint dwCatalogVersion;
        public IntPtr pcwszCatalogFilePath;
        public IntPtr pcwszMemberTag;
        public IntPtr pcwszMemberFilePath;
        public IntPtr hMemberFile;
        public IntPtr pbCalculatedFileHash;
        public uint cbCalculatedFileHash;
        public IntPtr pcCatalogContext;
        public IntPtr hCatAdmin;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WINTRUST_DATA
    {
        public uint cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public uint dwUIChoice;
        public uint fdwRevocationChecks;
        public uint dwUnionChoice;
        public IntPtr pInfo; // WINTRUST_FILE_INFO* or WINTRUST_CATALOG_INFO*
        public uint dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public uint dwProvFlags;
        public uint dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CATALOG_INFO
    {
        public uint cbStruct;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string wszCatalogFile;
    }

    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern int WinVerifyTrust(IntPtr hwnd, ref Guid action, ref WINTRUST_DATA data);

    [DllImport("wintrust.dll")]
    public static extern IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

    [DllImport("wintrust.dll")]
    public static extern IntPtr WTHelperGetProvSignerFromChain(IntPtr provData, uint signerIndex, bool counterSigner, uint counterSignerIndex);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern bool CryptCATAdminAcquireContext2(out IntPtr catAdmin, IntPtr subsystem, string? hashAlgorithm, IntPtr strongHashPolicy, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern bool CryptCATAdminReleaseContext(IntPtr catAdmin, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr catAdmin, IntPtr file, ref uint hashSize, [Out] byte[]? hash, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr catAdmin, byte[] hash, uint hashSize, uint flags, ref IntPtr prevCatInfo);

    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern bool CryptCATCatalogInfoFromContext(IntPtr catInfo, ref CATALOG_INFO info, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    public static extern bool CryptCATAdminReleaseCatalogContext(IntPtr catAdmin, IntPtr catInfo, uint flags);

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode)]
    public static extern int CertGetNameStringW(IntPtr certContext, uint type, uint flags, IntPtr typePara, StringBuilder name, int size);
}
