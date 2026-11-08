using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace XINSkan.Platform.Windows.Native;

/// <summary>
/// Every Win32 import of XIN SKAN. Deliberately small: no WriteFile, DeleteFile, MoveFile, SetFileTime,
/// RegSetValue or service/process control is imported anywhere in the product. SecurityTests verify that
/// no other assembly declares P/Invoke methods.
/// </summary>
[SupportedOSPlatform("windows")]
internal static partial class NativeMethods
{
    internal const uint GenericRead = 0x8000_0000;
    internal const uint FileShareRead = 0x1;
    internal const uint FileShareWrite = 0x2;
    internal const uint FileShareDelete = 0x4;
    internal const uint OpenExisting = 3;
    internal const uint FileFlagBackupSemantics = 0x0200_0000;
    internal const uint FileFlagSequentialScan = 0x0800_0000;

    /// <summary>Read sharing for all three modes so XIN SKAN never blocks the investigated system's own writers.</summary>
    internal const uint ShareAll = FileShareRead | FileShareWrite | FileShareDelete;

    internal const int ErrorFileNotFound = 2;
    internal const int ErrorPathNotFound = 3;

    /// <summary>BY_HANDLE_FILE_INFORMATION: FILETIME members are two DWORDs, so the struct is 4-byte packed (52 bytes).</summary>
    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    internal struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public ulong CreationTime;
        public ulong LastAccessTime;
        public ulong LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WintrustFileInfo
    {
        public uint StructSize;
        public IntPtr FilePath;
        public IntPtr FileHandle;
        public IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct WintrustData
    {
        public uint StructSize;
        public IntPtr PolicyCallbackData;
        public IntPtr SipClientData;
        public uint UiChoice;
        public uint RevocationChecks;
        public uint UnionChoice;
        public IntPtr File;
        public uint StateAction;
        public IntPtr StateData;
        public IntPtr UrlReference;
        public uint ProviderFlags;
        public uint UiContext;
        public IntPtr SignatureSettings;
    }

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [LibraryImport("kernel32.dll", EntryPoint = "DeviceIoControl", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static unsafe partial bool DeviceIoControl(
        SafeFileHandle device,
        uint ioControlCode,
        void* inBuffer,
        uint inBufferSize,
        void* outBuffer,
        uint outBufferSize,
        out uint bytesReturned,
        IntPtr overlapped);

    [LibraryImport("kernel32.dll", EntryPoint = "GetFileInformationByHandle", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static unsafe partial bool GetFileInformationByHandle(SafeFileHandle file, ByHandleFileInformation* information);

    /// <summary>Verifies an embedded Authenticode signature. Called only with revocation checks off and cache-only URL retrieval.</summary>
    [LibraryImport("wintrust.dll", EntryPoint = "WinVerifyTrust")]
    internal static unsafe partial int WinVerifyTrust(IntPtr window, Guid* action, WintrustData* data);

    [LibraryImport("kernel32.dll", EntryPoint = "GetVolumeInformationW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static unsafe partial bool GetVolumeInformation(
        string rootPathName,
        char* volumeNameBuffer,
        uint volumeNameSize,
        out uint volumeSerialNumber,
        out uint maximumComponentLength,
        out uint fileSystemFlags,
        char* fileSystemNameBuffer,
        uint fileSystemNameSize);
}
