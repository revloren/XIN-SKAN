namespace XINSkan.Core.Permissions;

/// <summary>System access an analyzer may need. Probed once per investigation (see ICapabilityProbe).</summary>
public enum Capability
{
    /// <summary>The process runs elevated.</summary>
    Administrator,

    /// <summary>A volume can be opened for raw sector reads (\\.\C:).</summary>
    RawVolumeRead,

    /// <summary>The USN change journal of a volume can be queried and read.</summary>
    UsnJournalRead,

    /// <summary>System registry hives (SYSTEM, SOFTWARE, Amcache) can be read.</summary>
    SystemRegistryHives,

    /// <summary>Profiles of users other than the current one can be read.</summary>
    OtherUserProfiles,

    /// <summary>The Security event log can be read.</summary>
    SecurityEventLog,
}

/// <summary>
/// Collection that goes beyond the device's own artifacts and needs the owner's explicit, recorded consent.
/// </summary>
public enum Consent
{
    /// <summary>Live network monitoring (connections, per-process traffic). Never packet contents.</summary>
    NetworkMonitoring,

    /// <summary>Download entries from browser history (only downloads, never cookies, passwords or browsing pages).</summary>
    BrowserDownloadHistory,

    /// <summary>Local metadata of cloud sync clients.</summary>
    CloudClientMetadata,

    /// <summary>Packing collected materials into an archive alongside the report.</summary>
    EvidenceArchive,

    /// <summary>Outbound requests (official Minecraft manifests, signature database updates).</summary>
    OutboundRequests,
}
