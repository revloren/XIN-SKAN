using System.Runtime.Versioning;
using Microsoft.Win32;
using XINSkan.Analyzers.Execution;
using XINSkan.Platform.Windows.EventLog;
using XINSkan.Platform.Windows.IO;
using XINSkan.Platform.Windows.Registry;
using XINSkan.Security;

namespace XINSkan.Investigation;

/// <summary>HKEY_LOCAL_MACHINE of the live system, read only (RegistryReader opens every key without write access).</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsMachineRegistry : IRegistryView
{
    public static readonly WindowsMachineRegistry Instance = new();

    public IReadOnlyList<RegistryEntry>? Values(string key)
    {
        try
        {
            return RegistryReader.ReadValues(RegistryHive.LocalMachine, key)?
                .Select(v => new RegistryEntry(v.Name, v.Value))
                .ToList();
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return null;
        }
    }

    public IReadOnlyList<string>? SubKeys(string key)
    {
        try
        {
            return RegistryReader.ReadSubKeyNames(RegistryHive.LocalMachine, key);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return null;
        }
    }

    public long? LastWriteTime(string key)
    {
        try
        {
            return RegistryReader.ReadLastWriteTime(RegistryHive.LocalMachine, key);
        }
        catch (Exception ex) when (ex is UnauthorizedAccessException or System.Security.SecurityException or IOException)
        {
            return null;
        }
    }
}

/// <summary>The volumes mounted now, with device paths and serials (query only).</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsVolumeDirectory : IVolumeDirectory
{
    public static readonly WindowsVolumeDirectory Instance = new();

    public IReadOnlyList<KnownVolume> Volumes() =>
        VolumeNames.List().Select(v => new KnownVolume(v.Drive, v.DevicePath, v.Serial, v.Type == DriveType.Removable)).ToList();
}

/// <summary>Used where no volumes can be listed (tests, other platforms).</summary>
public sealed class NoVolumeDirectory : IVolumeDirectory
{
    public static readonly NoVolumeDirectory Instance = new();

    public IReadOnlyList<KnownVolume> Volumes() => [];
}

/// <summary>Writes every machine registry key the analyzers open to the audit log.</summary>
public sealed class AuditingRegistryView(IRegistryView inner, AuditLogger log) : IRegistryView
{
    private readonly HashSet<string> _logged = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyList<RegistryEntry>? Values(string key)
    {
        var result = inner.Values(key);
        Log(key, "KEY_QUERY_VALUE", result is not null);
        return result;
    }

    public IReadOnlyList<string>? SubKeys(string key)
    {
        var result = inner.SubKeys(key);
        Log(key, "KEY_ENUMERATE_SUB_KEYS", result is not null);
        return result;
    }

    public long? LastWriteTime(string key) => inner.LastWriteTime(key);

    private void Log(string key, string access, bool ok)
    {
        lock (_logged)
        {
            if (_logged.Add(access + "|" + key))
            {
                log.Record("read-registry", @"HKLM\" + key, access + " (read only)", ok ? "ok" : "not-found");
            }
        }
    }
}

/// <summary>The live event logs through the Windows Event Log API (query and render only).</summary>
[SupportedOSPlatform("windows")]
public sealed class WindowsEventLogSource : IEventLogSource
{
    public static readonly WindowsEventLogSource Instance = new();

    private const int ChannelNotFound = 15007;
    private const int AccessDenied = 5;

    public EventQueryResult Query(string channel, string xpath, int max)
    {
        try
        {
            var events = EventLogQuery.Query(channel, xpath, newestFirst: false, max: max + 1).ToList();
            var truncated = events.Count > max;
            return new EventQueryResult(truncated ? events[..max] : events, null, Truncated: truncated);
        }
        catch (System.ComponentModel.Win32Exception ex)
        {
            return ex.NativeErrorCode switch
            {
                ChannelNotFound => new EventQueryResult([], "журнала нет на этой системе", ChannelMissing: true),
                AccessDenied => new EventQueryResult([], "нет доступа (нужны права администратора)"),
                _ => new EventQueryResult([], ex.Message),
            };
        }
    }

    public DateTimeOffset? Oldest(string channel)
    {
        try
        {
            var first = EventLogQuery.Query(channel, "*", newestFirst: false, max: 1).FirstOrDefault();
            return first is null ? null : EventXml.Parse(first)?.TimeCreated;
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return null;
        }
    }
}

/// <summary>Writes every event log query to the audit log.</summary>
public sealed class AuditingEventLogSource(IEventLogSource inner, AuditLogger log) : IEventLogSource
{
    public EventQueryResult Query(string channel, string xpath, int max)
    {
        var result = inner.Query(channel, xpath, max);
        log.Record("read-eventlog", channel + " " + xpath, "EvtQuery/EvtRender (read only)", result.Failure is null ? $"ok ({result.Events.Count})" : result.ChannelMissing ? "not-found" : "denied", result.Failure);
        return result;
    }

    public DateTimeOffset? Oldest(string channel) => inner.Oldest(channel);
}
