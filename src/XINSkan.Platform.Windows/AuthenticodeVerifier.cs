using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using XINSkan.Core.IO;
using XINSkan.Platform.Windows.IO;
using XINSkan.Platform.Windows.Native;

namespace XINSkan.Platform.Windows;

/// <summary>
/// Verifies the embedded Authenticode signature of a file with WinVerifyTrust, offline: revocation checks are
/// off and URL retrieval is limited to the local cache, so verification never reaches the network. The file is
/// passed as XIN SKAN's own read handle (full sharing), so verification does not block other processes.
/// </summary>
/// <remarks>
/// Catalog-signed files (many Windows components) carry no embedded signature and are reported as NotSigned;
/// checking catalogs is a separate, not yet implemented step. The signer's name is not extracted yet (TODO).
/// </remarks>
[SupportedOSPlatform("windows")]
public sealed class AuthenticodeVerifier : ISignatureVerifier
{
    private const uint WtdUiNone = 2;
    private const uint WtdRevokeNone = 0;
    private const uint WtdChoiceFile = 1;
    private const uint WtdStateActionVerify = 1;
    private const uint WtdStateActionClose = 2;
    private const uint WtdRevocationCheckNone = 0x10;
    private const uint WtdCacheOnlyUrlRetrieval = 0x1000;

    private static Guid _genericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    public static readonly AuthenticodeVerifier Instance = new();

    public unsafe SignatureResult Verify(string path)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        using var handle = ReadOnlyFile.OpenHandle(path);
        var pathPtr = Marshal.StringToHGlobalUni(path);
        try
        {
            var file = new NativeMethods.WintrustFileInfo
            {
                StructSize = (uint)sizeof(NativeMethods.WintrustFileInfo),
                FilePath = pathPtr,
                FileHandle = handle.DangerousGetHandle(),
                KnownSubject = IntPtr.Zero,
            };
            var data = new NativeMethods.WintrustData
            {
                StructSize = (uint)sizeof(NativeMethods.WintrustData),
                UiChoice = WtdUiNone,
                RevocationChecks = WtdRevokeNone,
                UnionChoice = WtdChoiceFile,
                File = (IntPtr)(&file),
                StateAction = WtdStateActionVerify,
                ProviderFlags = WtdRevocationCheckNone | WtdCacheOnlyUrlRetrieval,
            };

            int result;
            fixed (Guid* action = &_genericVerifyV2)
            {
                result = NativeMethods.WinVerifyTrust(IntPtr.Zero, action, &data);
                // Release the verification state; its result carries no information about the file.
                data.StateAction = WtdStateActionClose;
                _ = NativeMethods.WinVerifyTrust(IntPtr.Zero, action, &data);
            }

            GC.KeepAlive(handle);
            return Interpret(result);
        }
        finally
        {
            Marshal.FreeHGlobal(pathPtr);
        }
    }

    /// <summary>Maps WinVerifyTrust HRESULTs to statuses. Public for tests.</summary>
    public static SignatureResult Interpret(int hresult) => unchecked((uint)hresult) switch
    {
        0 => new(SignatureStatus.Valid, "Embedded signature is valid (revocation not checked, offline)."),
        0x800B0100 => new(SignatureStatus.NotSigned, "No embedded signature (TRUST_E_NOSIGNATURE). Catalog-signed system files also appear here."),
        0x800B0003 => new(SignatureStatus.NotSigned, "The file type cannot carry an Authenticode signature (TRUST_E_SUBJECT_FORM_UNKNOWN)."),
        0x80096010 => new(SignatureStatus.Tampered, "The file was changed after it was signed (TRUST_E_BAD_DIGEST)."),
        0x800B0109 => new(SignatureStatus.Untrusted, "Signed, but the root certificate is not trusted (CERT_E_UNTRUSTEDROOT)."),
        0x800B0101 => new(SignatureStatus.Untrusted, "Signed with an expired certificate and no valid timestamp (CERT_E_EXPIRED)."),
        0x800B0111 => new(SignatureStatus.Untrusted, "The signer is explicitly distrusted (TRUST_E_EXPLICIT_DISTRUST)."),
        0x800B010A => new(SignatureStatus.Untrusted, "The certificate chain could not be built (CERT_E_CHAINING)."),
        0x800B0004 => new(SignatureStatus.Untrusted, "The subject is not trusted for this action (TRUST_E_SUBJECT_NOT_TRUSTED)."),
        0x80092026 => new(SignatureStatus.Untrusted, "Blocked by the system's security settings (CRYPT_E_SECURITY_SETTINGS)."),
        var other => new(SignatureStatus.Error, $"WinVerifyTrust returned 0x{other:X8}."),
    };
}
