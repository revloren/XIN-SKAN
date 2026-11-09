using System.Globalization;
using System.Xml;
using System.Xml.Linq;

namespace XINSkan.Analyzers.Execution;

/// <summary>One event as rendered by the Event Log service, reduced to what the analyzers use.</summary>
/// <param name="Data">EventData/Data by name (unnamed items by position "0", "1", …) and UserData leaf elements.</param>
public sealed record EventRecord(string Channel, int EventId, string? Provider, DateTimeOffset? TimeCreated, long? RecordId, string? UserSid, string? Computer, IReadOnlyDictionary<string, string> Data)
{
    public string? Get(string name) => Data.TryGetValue(name, out var v) && v.Length > 0 ? v : null;
}

/// <summary>Result of one query: the events as XML, or why the channel could not be read.</summary>
public sealed record EventQueryResult(IReadOnlyList<string> Events, string? Failure, bool ChannelMissing = false, bool Truncated = false);

/// <summary>The live event logs, read only.</summary>
public interface IEventLogSource
{
    EventQueryResult Query(string channel, string xpath, int max);

    /// <summary>Time of the oldest event still in the channel, or null.</summary>
    DateTimeOffset? Oldest(string channel);
}

/// <summary>Used where there are no event logs (tests, other platforms).</summary>
public sealed class NoEventLogs : IEventLogSource
{
    public static readonly NoEventLogs Instance = new();

    public EventQueryResult Query(string channel, string xpath, int max) => new([], "Журналы событий здесь недоступны.", ChannelMissing: true);

    public DateTimeOffset? Oldest(string channel) => null;
}

/// <summary>Parses the event XML schema (http://schemas.microsoft.com/win/2004/08/events/event). Never throws.</summary>
public static class EventXml
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    private static readonly XmlReaderSettings Settings = new()
    {
        DtdProcessing = DtdProcessing.Prohibit,
        XmlResolver = null,
        MaxCharactersInDocument = 4 * 1024 * 1024,
        IgnoreComments = true,
    };

    public static EventRecord? Parse(string xml)
    {
        ArgumentNullException.ThrowIfNull(xml);
        XElement root;
        try
        {
            using var reader = XmlReader.Create(new StringReader(xml), Settings);
            root = XDocument.Load(reader).Root!;
        }
        catch (XmlException)
        {
            return null;
        }

        var system = root.Element(Ns + "System");
        if (system is null || !int.TryParse(system.Element(Ns + "EventID")?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var id))
        {
            return null;
        }

        DateTimeOffset? time = DateTimeOffset.TryParse(system.Element(Ns + "TimeCreated")?.Attribute("SystemTime")?.Value, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var t)
            ? t
            : null;
        long? recordId = long.TryParse(system.Element(Ns + "EventRecordID")?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var r) ? r : null;

        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var position = 0;
        foreach (var d in root.Element(Ns + "EventData")?.Elements(Ns + "Data") ?? [])
        {
            var name = d.Attribute("Name")?.Value;
            data.TryAdd(string.IsNullOrEmpty(name) ? position.ToString(CultureInfo.InvariantCulture) : name, d.Value);
            position++;
        }

        // UserData has a provider-specific element; its leaf elements carry the values (log cleared: SubjectUserName, …).
        foreach (var leaf in root.Element(Ns + "UserData")?.Descendants().Where(e => !e.HasElements) ?? [])
        {
            data.TryAdd(leaf.Name.LocalName, leaf.Value);
        }

        return new EventRecord(
            system.Element(Ns + "Channel")?.Value ?? string.Empty,
            id,
            system.Element(Ns + "Provider")?.Attribute("Name")?.Value,
            time,
            recordId,
            system.Element(Ns + "Security")?.Attribute("UserID")?.Value,
            system.Element(Ns + "Computer")?.Value,
            data);
    }
}
