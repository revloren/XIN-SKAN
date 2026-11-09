using XINSkan.Analyzers.Execution;
using XINSkan.Analyzers.History;
using XINSkan.Core.Pipeline;
using XINSkan.Models;

namespace XINSkan.ExecutionTests;

/// <summary>Event XML as the Event Log service renders it (schema of http://schemas.microsoft.com/win/2004/08/events/event).</summary>
internal static class Events
{
    private static int _record = 1000;

    public static string Xml(string channel, int id, string provider, DateTime time, string body, string? sid = null) =>
        $"""
        <Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>
          <System>
            <Provider Name='{provider}'/>
            <EventID>{id}</EventID><Version>0</Version><Level>4</Level>
            <TimeCreated SystemTime='{time:yyyy-MM-ddTHH:mm:ss.fffffff}Z'/>
            <EventRecordID>{++_record}</EventRecordID>
            <Channel>{channel}</Channel><Computer>PLAYER-PC</Computer>
            {(sid is null ? "<Security/>" : $"<Security UserID='{sid}'/>")}
          </System>
          {body}
        </Event>
        """;

    public static string Data(params (string Name, string Value)[] items) =>
        "<EventData>" + string.Concat(items.Select(i => i.Name.Length == 0 ? $"<Data>{i.Value}</Data>" : $"<Data Name='{i.Name}'>{i.Value}</Data>")) + "</EventData>";
}

internal sealed class TestEventLogs : IEventLogSource
{
    public Dictionary<string, List<string>> Channels { get; } = new(StringComparer.OrdinalIgnoreCase);

    public List<string> Queries { get; } = [];

    public TestEventLogs Add(string channel, string xml)
    {
        if (!Channels.TryGetValue(channel, out var list))
        {
            Channels[channel] = list = [];
        }

        list.Add(xml);
        return this;
    }

    public EventQueryResult Query(string channel, string xpath, int max)
    {
        Queries.Add(channel + " " + xpath);
        return Channels.TryGetValue(channel, out var list) ? new EventQueryResult(list, null) : new EventQueryResult([], "журнала нет", ChannelMissing: true);
    }

    public DateTimeOffset? Oldest(string channel) => Channels.ContainsKey(channel) ? new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero) : null;
}

public sealed class EventLogTests
{
    private static readonly DateTime At = new(2026, 11, 7, 19, 5, 30, DateTimeKind.Utc);

    private static HistoryOptions Options => new() { Volumes = ["C:"], UsersRoot = @"C:\Users", CurrentProfile = @"C:\Users\player", TempFolders = [@"C:\Windows\Temp"] };

    [Fact]
    public void Event_xml_is_parsed_with_named_unnamed_and_user_data()
    {
        var e = EventXml.Parse(Events.Xml("Application", 1000, "Application Error", At, Events.Data(("", "javaw.exe"), ("", "8.0.3810.9"), ("", "x"), ("", "inject.dll"))))!;
        Assert.Equal(1000, e.EventId);
        Assert.Equal("Application", e.Channel);
        Assert.Equal("Application Error", e.Provider);
        Assert.Equal(new DateTimeOffset(At), e.TimeCreated);
        Assert.Equal("javaw.exe", e.Get("0"));
        Assert.Equal("inject.dll", e.Get("3"));

        var cleared = EventXml.Parse(Events.Xml("Security", 1102, "Microsoft-Windows-Eventlog", At,
            "<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserSid>S-1-5-21-1</SubjectUserSid><SubjectUserName>player</SubjectUserName><SubjectDomainName>PLAYER-PC</SubjectDomainName></LogFileCleared></UserData>"))!;
        Assert.Equal("player", cleared.Get("SubjectUserName"));

        Assert.Null(EventXml.Parse("<not xml"));
        Assert.Null(EventXml.Parse("<?xml version='1.0'?><!DOCTYPE x [<!ENTITY a 'b'>]><Event/>"));
        Assert.Null(EventXml.Parse("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>x</EventID></System></Event>"));
    }

    [Fact]
    public async Task Cleared_logs_detections_exclusions_crashes_drivers_and_processes_are_interpreted()
    {
        var logs = new TestEventLogs()
            .Add("System", Events.Xml("System", 104, "Microsoft-Windows-Eventlog", At,
                "<UserData><LogFileCleared xmlns='http://manifests.microsoft.com/win/2004/08/windows/eventlog'><SubjectUserName>player</SubjectUserName><SubjectDomainName>PLAYER-PC</SubjectDomainName><Channel>Application</Channel><BackupPath></BackupPath></LogFileCleared></UserData>"))
            .Add("System", Events.Xml("System", 7045, "Service Control Manager", At, Events.Data(("ServiceName", "KDU"), ("ImagePath", @"\??\C:\Users\player\Downloads\kdu\drv64.sys"), ("ServiceType", "kernel mode driver"), ("StartType", "demand start"), ("AccountName", ""))))
            .Add("System", Events.Xml("System", 7045, "Service Control Manager", At, Events.Data(("ServiceName", "Spooler2"), ("ImagePath", @"C:\Windows\System32\spoolsv.exe"), ("ServiceType", "user mode service"))))
            .Add("Application", Events.Xml("Application", 1000, "Application Error", At, Events.Data(
                ("", "javaw.exe"), ("", "8.0.3810.9"), ("", "65c1f6a2"), ("", "inject.dll"), ("", "0.0.0.0"), ("", "00000000"), ("", "c0000005"), ("", "0000000000001234"),
                ("", "0x1a2b"), ("", "0x01db3123"), ("", @"C:\Program Files\Java\jre\bin\javaw.exe"), ("", @"C:\Users\player\AppData\Local\Temp\inject.dll"), ("", "id"), ("", ""), ("", ""))))
            .Add("Application", Events.Xml("Application", 1000, "Application Error", At, Events.Data(("", "explorer.exe"), ("", "10"), ("", "x"), ("", "ntdll.dll"), ("", ""), ("", ""), ("", ""), ("", ""), ("", ""), ("", ""), ("", @"C:\Windows\explorer.exe"), ("", @"C:\Windows\System32\ntdll.dll"))))
            .Add("Security", Events.Xml("Security", 4688, "Microsoft-Windows-Security-Auditing", At, Events.Data(("SubjectUserSid", "S-1-5-21-1-1001"), ("NewProcessName", @"C:\Users\player\Downloads\loader.exe"), ("CommandLine", @"loader.exe --inject javaw.exe"), ("ParentProcessName", @"C:\Windows\explorer.exe"))))
            .Add("Security", Events.Xml("Security", 4688, "Microsoft-Windows-Security-Auditing", At, Events.Data(("NewProcessName", @"C:\Windows\System32\svchost.exe"))))
            .Add(EventLogAnalyzer.Defender, Events.Xml(EventLogAnalyzer.Defender, 1116, "Microsoft-Windows-Windows Defender", At, Events.Data(
                ("Threat Name", "HackTool:Win32/Injector"), ("Severity Name", "High"), ("Category Name", "Tool"), ("Path", @"file:_C:\Users\player\Downloads\loader.exe; containerfile:_C:\Users\player\Downloads\pack.zip->loader.exe"), ("Process Name", @"C:\Windows\explorer.exe"), ("Detection User", @"PLAYER-PC\player"))))
            .Add(EventLogAnalyzer.Defender, Events.Xml(EventLogAnalyzer.Defender, 5007, "Microsoft-Windows-Windows Defender", At, Events.Data(
                ("Old Value", ""), ("New Value", @"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\player\AppData\Roaming\.minecraft = 0x0"))))
            .Add(EventLogAnalyzer.Defender, Events.Xml(EventLogAnalyzer.Defender, 5007, "Microsoft-Windows-Windows Defender", At, Events.Data(
                ("Old Value", @"HKLM\SOFTWARE\Microsoft\Windows Defender\Scan\AvgCPULoadFactor = 0x32"), ("New Value", @"HKLM\SOFTWARE\Microsoft\Windows Defender\Scan\AvgCPULoadFactor = 0x14"))))
            .Add(EventLogAnalyzer.Defender, Events.Xml(EventLogAnalyzer.Defender, 5001, "Microsoft-Windows-Windows Defender", At, Events.Data()))
            .Add(EventLogAnalyzer.Defender, "<broken");

        var sink = await PrefetchAnalyzerTests.RunAsync(new EventLogAnalyzer(Options, logs, new TestVolumes()));
        Assert.Equal(4, logs.Queries.Count);
        Assert.Contains("System *[System[(EventID=104 or EventID=7045)]]", logs.Queries);

        var cleared = sink.Evidence.Single(e => e.Attributes["EventLog.EventId"] == "104");
        Assert.Equal(Confidence.Low, cleared.Confidence);
        Assert.Equal("Application", cleared.Attributes["EventLog.ClearedChannel"]);
        Assert.Equal(@"PLAYER-PC\player", cleared.Attributes["EventLog.User"]);
        Assert.Equal(new DateTimeOffset(At), cleared.Timestamp!.ValueUtc);
        Assert.Equal(EvidenceSourceKind.EventLog, cleared.Source.Kind);

        var driver = sink.Evidence.Single(e => e.Attributes["EventLog.EventId"] == "7045");
        Assert.Equal(@"C:\Users\player\Downloads\kdu\drv64.sys", driver.Target.RecordedPath);
        Assert.Equal(Confidence.Low, driver.Confidence);
        Assert.Equal("KDU", driver.Attributes["Service.Name"]);

        var crash = sink.Evidence.Single(e => e.Attributes["EventLog.EventId"] == "1000" && e.EventType == EvidenceEventType.Executed);
        Assert.Equal(@"C:\Program Files\Java\jre\bin\javaw.exe", crash.Target.RecordedPath);
        Assert.Equal("inject.dll", crash.Attributes["Crash.Module"]);
        var injected = sink.Evidence.Single(e => e.EventType == EvidenceEventType.Loaded);
        Assert.Equal(@"C:\Users\player\AppData\Local\Temp\inject.dll", injected.Target.RecordedPath);
        Assert.Equal(Confidence.Informational, injected.Confidence);

        var process = sink.Evidence.Single(e => e.Attributes["EventLog.EventId"] == "4688");
        Assert.Equal(EvidenceEventType.Executed, process.EventType);
        Assert.Equal("loader.exe --inject javaw.exe", process.Attributes["Process.CommandLine"]);
        Assert.Equal("S-1-5-21-1-1001", process.UserSid);

        var detection = sink.Evidence.Single(e => e.Attributes["EventLog.EventId"] == "1116");
        Assert.Equal("HackTool:Win32/Injector", detection.Attributes["Defender.Threat"]);
        Assert.Equal(@"C:\Users\player\Downloads\loader.exe", detection.Target.RecordedPath);
        Assert.Equal(Confidence.Informational, detection.Confidence);

        var exclusion = sink.Evidence.Single(e => e.Attributes["EventLog.EventId"] == "5007");
        Assert.Equal(@"C:\Users\player\AppData\Roaming\.minecraft", exclusion.Target.RecordedPath);
        Assert.Equal("Paths", exclusion.Attributes["Defender.ExclusionType"]);
        Assert.Equal(Confidence.Low, exclusion.Confidence);
        Assert.Equal(Confidence.Low, sink.Evidence.Single(e => e.Attributes["EventLog.EventId"] == "5001").Confidence);

        Assert.DoesNotContain(sink.Evidence, e => e.Target.RecordedPath?.Contains("System32", StringComparison.OrdinalIgnoreCase) == true || e.Target.FileName == "explorer.exe");
        Assert.DoesNotContain(sink.Evidence, e => e.Confidence > Confidence.Low);

        Assert.Equal(4, sink.Coverage.Count);
        var defender = sink.Coverage.Single(c => c.Scope == EventLogAnalyzer.Defender);
        Assert.Equal(CollectionStatus.Partial, defender.Status);
        Assert.Contains(defender.Limitations, l => l.Code == "EVENTLOG.DAMAGED");
        Assert.Equal(new DateTimeOffset(2026, 10, 1, 0, 0, 0, TimeSpan.Zero), defender.EarliestUtc);
    }

    [Fact]
    public async Task Missing_channels_and_missing_process_audit_are_reported()
    {
        var logs = new TestEventLogs().Add("Security", Events.Xml("Security", 1102, "Microsoft-Windows-Eventlog", At, "<UserData/>"));
        var sink = await PrefetchAnalyzerTests.RunAsync(new EventLogAnalyzer(Options, logs, new TestVolumes()));
        Assert.Equal(CollectionStatus.Skipped, sink.Coverage.Single(c => c.Scope == "System").Status);
        Assert.Contains(sink.Coverage.Single(c => c.Scope == "Security").Limitations, l => l.Code == "EVENTLOG.NO_PROCESS_AUDIT");
        Assert.Single(sink.Evidence);
    }

    [Theory]
    [InlineData(@"""C:\Program Files\App\svc.exe"" -k run", @"C:\Program Files\App\svc.exe")]
    [InlineData(@"C:\Users\p\Temp\x.exe /service", @"C:\Users\p\Temp\x.exe")]
    [InlineData(@"\??\C:\Users\p\drv.sys", @"C:\Users\p\drv.sys")]
    [InlineData(@"\SystemRoot\System32\drivers\a.sys", null)]
    [InlineData(@"system32\DRIVERS\b.sys", null)]
    [InlineData("", null)]
    public void Service_command_lines_give_the_executable(string command, string? expected) =>
        Assert.Equal(expected, EventLogAnalyzer.ExecutablePath(command));

    [Theory]
    [InlineData(@"file:_C:\a\b.jar", @"C:\a\b.jar")]
    [InlineData(@"containerfile:_C:\a\pack.zip; file:_C:\a\pack.zip->x.class", @"C:\a\pack.zip")]
    [InlineData(@"regkey:_HKLM\Software\X", null)]
    public void Defender_paths_are_extracted(string raw, string? expected) => Assert.Equal(expected, EventLogAnalyzer.DefenderPath(raw));
}
