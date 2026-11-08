using Microsoft.Data.Sqlite;
using XINSkan.Core.Pipeline;
using XINSkan.Models;

namespace XINSkan.Storage;

/// <summary>
/// Read-only access to an investigation database, for correlation, reports and the interface.
/// Opened with SQLITE_OPEN_READONLY: reading a finished investigation cannot change it.
/// </summary>
public sealed class InvestigationReader : IDisposable
{
    private readonly SqliteConnection _connection;

    private InvestigationReader(SqliteConnection connection) => _connection = connection;

    public static InvestigationReader Open(string databasePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(databasePath);
        if (!System.IO.File.Exists(databasePath))
        {
            throw new FileNotFoundException("Investigation database not found.", databasePath);
        }

        var c = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString());
        c.Open();
        return new InvestigationReader(c);
    }

    public int SchemaVersion()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT Version FROM SchemaInfo LIMIT 1;";
        return Convert.ToInt32(cmd.ExecuteScalar(), System.Globalization.CultureInfo.InvariantCulture);
    }

    public InvestigationInfo ReadInfo()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT InvestigationId, StartedUtc, ToolVersion, Operator, MachineName, OsDescription, TimeZoneId FROM Investigations LIMIT 1;";
        using var r = cmd.ExecuteReader();
        if (!r.Read())
        {
            throw new InvalidDataException("The database has no investigation header.");
        }

        return new InvestigationInfo
        {
            InvestigationId = Ulid.Parse(r.GetString(0)),
            StartedUtc = DateTimeOffset.Parse(r.GetString(1), System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AdjustToUniversal),
            ToolVersion = r.GetString(2),
            Operator = Str(r, 3),
            MachineName = Str(r, 4),
            OsDescription = Str(r, 5),
            TimeZoneId = Str(r, 6),
        };
    }

    public long CountEvidence()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM Evidence;";
        return (long)cmd.ExecuteScalar()!;
    }

    /// <summary>All evidence in ID order (which is creation-time order).</summary>
    public IEnumerable<Evidence> ReadEvidence()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = """
            SELECT EvidenceId, InvestigationId, ModuleId, SourceKind, ArtifactPath, Parser, ParserVersion, Locator, EventType,
                   TsUtcTicks, TsField, TsPrecision, TsSourceZone, TsUncertaintyTicks, OtherTimestamps,
                   RecordedPath, NormalizedPath, FileName, VolumeSerial, MftEntry, MftSequence, Size, ObjectSha256, ArtifactSha256,
                   Confidence, Rationale, CollectionStatus, Description, Limitations, UserSid, Attributes, CollectedAtUtcTicks
            FROM Evidence ORDER BY EvidenceId;
            """;
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            yield return new Evidence
            {
                EvidenceId = Ulid.Parse(r.GetString(0)),
                InvestigationId = Ulid.Parse(r.GetString(1)),
                ModuleId = r.GetString(2),
                Source = new SourceRef(Enum.Parse<EvidenceSourceKind>(r.GetString(3)), r.GetString(4), r.GetString(5), r.GetString(6)),
                Locator = r.GetString(7),
                EventType = Enum.Parse<EvidenceEventType>(r.GetString(8)),
                Timestamp = r.IsDBNull(9)
                    ? null
                    : new EvidenceTimestamp(Rows.FromTicks(r.GetInt64(9)), r.GetString(10), Enum.Parse<TimestampPrecision>(r.GetString(11)), Str(r, 12), TimeSpan.FromTicks(r.GetInt64(13))),
                OtherTimestamps = Rows.Timestamps(r.GetString(14)),
                Target = new ObjectRef
                {
                    RecordedPath = Str(r, 15),
                    NormalizedPath = Str(r, 16),
                    FileName = Str(r, 17),
                    VolumeSerial = Rows.Serial(Str(r, 18)),
                    MftEntry = r.IsDBNull(19) ? null : (ulong)r.GetInt64(19),
                    MftSequence = r.IsDBNull(20) ? null : (ushort)r.GetInt64(20),
                    Size = r.IsDBNull(21) ? null : r.GetInt64(21),
                },
                ObjectSha256 = r.IsDBNull(22) ? null : Sha256Hash.Parse(r.GetString(22)),
                ArtifactSha256 = r.IsDBNull(23) ? null : Sha256Hash.Parse(r.GetString(23)),
                Confidence = Enum.Parse<Confidence>(r.GetString(24)),
                Rationale = r.GetString(25),
                CollectionStatus = Enum.Parse<CollectionStatus>(r.GetString(26)),
                Description = r.GetString(27),
                Limitations = Rows.Limitations(r.GetString(28)),
                UserSid = Str(r, 29),
                Attributes = Rows.Attributes(r.GetString(30)),
                CollectedAtUtc = Rows.FromTicks(r.GetInt64(31)),
            };
        }
    }

    public IReadOnlyList<SourceCoverage> ReadCoverage()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT InvestigationId, ModuleId, SourceKind, Scope, Status, EarliestUtcTicks, LatestUtcTicks, ItemsRead, Limitations FROM SourceCoverage ORDER BY Id;";
        using var r = cmd.ExecuteReader();
        var list = new List<SourceCoverage>();
        while (r.Read())
        {
            list.Add(new SourceCoverage
            {
                InvestigationId = Ulid.Parse(r.GetString(0)),
                ModuleId = r.GetString(1),
                Source = Enum.Parse<EvidenceSourceKind>(r.GetString(2)),
                Scope = r.GetString(3),
                Status = Enum.Parse<CollectionStatus>(r.GetString(4)),
                EarliestUtc = r.IsDBNull(5) ? null : Rows.FromTicks(r.GetInt64(5)),
                LatestUtc = r.IsDBNull(6) ? null : Rows.FromTicks(r.GetInt64(6)),
                ItemsRead = r.IsDBNull(7) ? null : r.GetInt64(7),
                Limitations = Rows.Limitations(r.GetString(8)),
            });
        }

        return list;
    }

    public IReadOnlyList<ModuleResult> ReadModuleResults()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT ModuleId, State, StartedUtcTicks, FinishedUtcTicks, EvidenceCount, CoverageCount, Reason FROM ModuleResults ORDER BY Id;";
        using var r = cmd.ExecuteReader();
        var list = new List<ModuleResult>();
        while (r.Read())
        {
            list.Add(new ModuleResult
            {
                ModuleId = r.GetString(0),
                State = Enum.Parse<ModuleState>(r.GetString(1)),
                StartedUtc = r.IsDBNull(2) ? null : Rows.FromTicks(r.GetInt64(2)),
                FinishedUtc = r.IsDBNull(3) ? null : Rows.FromTicks(r.GetInt64(3)),
                EvidenceCount = r.GetInt64(4),
                CoverageCount = r.GetInt64(5),
                Reason = Str(r, 6),
            });
        }

        return list;
    }

    public IReadOnlyList<(string ModuleId, ModuleError Error)> ReadErrors()
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = "SELECT ModuleId, Message, ExceptionType, Location FROM ModuleErrors ORDER BY Id;";
        using var r = cmd.ExecuteReader();
        var list = new List<(string, ModuleError)>();
        while (r.Read())
        {
            list.Add((r.GetString(0), new ModuleError(r.GetString(1), Str(r, 2), Str(r, 3))));
        }

        return list;
    }

    /// <summary>Count of rows in a view or table defined by the schema (used by tests and diagnostics).</summary>
    public long Count(StorageView view)
    {
        using var cmd = _connection.CreateCommand();
        cmd.CommandText = view switch
        {
            StorageView.FileEvents => "SELECT COUNT(*) FROM FileEvents;",
            StorageView.ExecutionEvents => "SELECT COUNT(*) FROM ExecutionEvents;",
            _ => throw new ArgumentOutOfRangeException(nameof(view)),
        };
        return (long)cmd.ExecuteScalar()!;
    }

    public void Dispose() => _connection.Dispose();

    private static string? Str(SqliteDataReader r, int i) => r.IsDBNull(i) ? null : r.GetString(i);
}

public enum StorageView
{
    FileEvents,
    ExecutionEvents,
}
