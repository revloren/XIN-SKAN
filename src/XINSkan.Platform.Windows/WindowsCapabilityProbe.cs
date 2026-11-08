using System.ComponentModel;
using System.Runtime.Versioning;
using System.Security.Principal;
using Microsoft.Win32;
using XINSkan.Core.Permissions;
using XINSkan.Platform.Windows.IO;
using XINSkan.Platform.Windows.Registry;

namespace XINSkan.Platform.Windows;

/// <summary>
/// Probes what the current process can read on this machine. Each probe only opens and closes a read handle;
/// nothing is created, changed or enabled.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsCapabilityProbe : ICapabilityProbe
{
    private const int ErrorJournalNotActive = 1179;
    private const int ErrorJournalDeleteInProgress = 1178;

    private readonly string _systemDrive;

    public WindowsCapabilityProbe(string? systemDrive = null)
    {
        _systemDrive = (systemDrive ?? Environment.GetEnvironmentVariable("SystemDrive") ?? "C:")[..2];
    }

    public CapabilityState Probe(Capability capability) => capability switch
    {
        Capability.Administrator => ProbeAdministrator(),
        Capability.RawVolumeRead => ProbeRawVolume(),
        Capability.UsnJournalRead => ProbeUsnJournal(),
        Capability.SystemRegistryHives => ProbeSystemRegistry(),
        Capability.OtherUserProfiles => ProbeOtherProfiles(),
        Capability.SecurityEventLog => new CapabilityState(capability, false, "Not probed yet: the event log source is added in a later stage (TODO)."),
        _ => new CapabilityState(capability, false, "Unknown capability."),
    };

    private static CapabilityState ProbeAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var admin = new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        return new CapabilityState(Capability.Administrator, admin, admin ? "The process is elevated." : "The process is not running as administrator.");
    }

    private CapabilityState ProbeRawVolume()
    {
        try
        {
            using var volume = VolumeReader.Open(_systemDrive);
            Span<byte> boot = stackalloc byte[512];
            var read = volume.Read(0, boot);
            return new CapabilityState(Capability.RawVolumeRead, read == 512, read == 512 ? $"Volume {_systemDrive} can be read sector by sector." : "The boot sector could not be read.");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or Win32Exception)
        {
            return new CapabilityState(Capability.RawVolumeRead, false, ex.Message);
        }
    }

    private CapabilityState ProbeUsnJournal()
    {
        try
        {
            using var volume = VolumeReader.Open(_systemDrive);
            Span<byte> data = stackalloc byte[80];
            SafeIoControl.Invoke(volume.Handle, AllowedIoControl.QueryUsnJournal, default, data);
            return new CapabilityState(Capability.UsnJournalRead, true, $"The change journal of {_systemDrive} is active and readable.");
        }
        catch (Win32Exception ex) when (ex.NativeErrorCode is ErrorJournalNotActive or ErrorJournalDeleteInProgress)
        {
            return new CapabilityState(Capability.UsnJournalRead, false, $"The change journal of {_systemDrive} is not active (Win32 error {ex.NativeErrorCode}).");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException or Win32Exception)
        {
            return new CapabilityState(Capability.UsnJournalRead, false, ex.Message);
        }
    }

    private static CapabilityState ProbeSystemRegistry()
    {
        try
        {
            // BAM user settings are readable only by SYSTEM and Administrators: a good indicator for protected system keys.
            var ok = RegistryReader.KeyExists(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings")
                     || RegistryReader.KeyExists(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\bam\UserSettings");
            return new CapabilityState(Capability.SystemRegistryHives, ok, ok ? "Protected system registry keys are readable." : "BAM keys are absent or not readable.");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return new CapabilityState(Capability.SystemRegistryHives, false, ex.Message);
        }
    }

    private CapabilityState ProbeOtherProfiles()
    {
        var usersRoot = _systemDrive + @"\Users";
        var current = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
        try
        {
            var others = Directory.EnumerateDirectories(usersRoot)
                .Where(d => !string.Equals(d, current, StringComparison.OrdinalIgnoreCase))
                .Where(d => !Path.GetFileName(d).Equals("Public", StringComparison.OrdinalIgnoreCase)
                            && !Path.GetFileName(d).Equals("Default", StringComparison.OrdinalIgnoreCase)
                            && !Path.GetFileName(d).Equals("Default User", StringComparison.OrdinalIgnoreCase)
                            && !Path.GetFileName(d).Equals("All Users", StringComparison.OrdinalIgnoreCase))
                .ToList();
            if (others.Count == 0)
            {
                return new CapabilityState(Capability.OtherUserProfiles, true, "There are no other user profiles on this system.");
            }

            foreach (var profile in others)
            {
                _ = Directory.EnumerateFileSystemEntries(profile).Take(1).ToList();
            }

            return new CapabilityState(Capability.OtherUserProfiles, true, $"{others.Count} other profile(s) are readable.");
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or IOException)
        {
            return new CapabilityState(Capability.OtherUserProfiles, false, ex.Message);
        }
    }
}
