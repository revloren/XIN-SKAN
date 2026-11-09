using Microsoft.Data.Sqlite;
using XINSkan.Core.Pipeline;
using XINSkan.Models;
using XINSkan.Security;

namespace XINSkan.Storage;

/// <summary>
/// Durable sink of one investigation: a new SQLite database inside the investigation folder.
/// Records are buffered and written in transactions; <see cref="CheckpointAsync"/> writes everything pending
/// together with the module result in one transaction, so after a checkpoint the module's records survive a
/// crash, a cancellation or a failure of a later module.
/// </summary>
/// <remarks>
/// The database uses a persistent rollback journal (PRAGMA journal_mode=PERSIST) whose file is claimed through
/// <see cref="OutputSink"/> before SQLite opens it. SQLite therefore never creates or deletes files outside the
/// sink's accounting, and the integrity manifest lists every file in the folder.
/// </remarks>
public sealed class InvestigationStore : IInvestigationSink, ICorrelationSink, IDisposable
{
    public const string DatabaseFileName = "evidence.db";
    public const string JournalFileName = "evidence.db-journal";

    private readonly SqliteConnection _connection;
    private readonly TimeProvider _time;
    private readonly int _batchSize;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly List<Evidence> _evidence = [];
    private readonly List<SourceCoverage> _coverage = [];
    private readonly List<(string Module, ModuleError Error)> _errors = [];
    private bool _disposed;
    private int _disposeStarted;
    private string _synchronous = "FULL";

    private InvestigationStore(SqliteConnection connection, string path, InvestigationInfo info, TimeProvider time, int batchSize)
    {
        _connection = connection;
        DatabasePath = path;
        Info = info;
        _time = time;
        _batchSize = batchSize;
    }

    public string DatabasePath { get; }

    /// <summary>Write statistics of this store (for diagnostics and performance tests).</summary>
    public StoreStatistics Stats { get; } = new();

    public InvestigationInfo Info { get; }

    /// <summary>Creates the database for a new investigation. Fails if the folder already holds one.</summary>
    public static InvestigationStore Create(OutputSink sink, InvestigationInfo info, TimeProvider time, int batchSize = 5000)
    {
        ArgumentNullException.ThrowIfNull(sink);
        ArgumentNullException.ThrowIfNull(info);
        ArgumentNullException.ThrowIfNull(time);
        ArgumentOutOfRangeException.ThrowIfLessThan(batchSize, 1);

        var path = sink.ReserveNewFile(DatabaseFileName);
        sink.ReserveNewFile(JournalFileName);

        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadWrite,
            Pooling = false,
            ForeignKeys = true,
        }.ToString());
        connection.Open();

        try
        {
            Execute(connection, "PRAGMA journal_mode = PERSIST;");
            Execute(connection, "PRAGMA synchronous = FULL;");
            using (var tx = connection.BeginTransaction())
            {
                Execute(connection, Schema.Create, tx);

                using var meta = connection.CreateCommand();
                meta.Transaction = tx;
                meta.CommandText = "INSERT INTO SchemaInfo (Version, CreatedUtc) VALUES ($v, $c);";
                meta.Parameters.AddWithValue("$v", Schema.Version);
                meta.Parameters.AddWithValue("$c", Rows.Utc(time.GetUtcNow()));
                meta.ExecuteNonQuery();

                using var inv = connection.CreateCommand();
                inv.Transaction = tx;
                inv.CommandText = """
                    INSERT INTO Investigations (InvestigationId, StartedUtc, ToolVersion, Operator, MachineName, OsDescription, TimeZoneId)
                    VALUES ($id, $started, $tool, $op, $machine, $os, $tz);
                    """;
                inv.Parameters.AddWithValue("$id", info.InvestigationId.Value);
                inv.Parameters.AddWithValue("$started", Rows.Utc(info.StartedUtc));
                inv.Parameters.AddWithValue("$tool", info.ToolVersion);
                inv.Parameters.AddWithValue("$op", (object?)info.Operator ?? DBNull.Value);
                inv.Parameters.AddWithValue("$machine", (object?)info.MachineName ?? DBNull.Value);
                inv.Parameters.AddWithValue("$os", (object?)info.OsDescription ?? DBNull.Value);
                inv.Parameters.AddWithValue("$tz", (object?)info.TimeZoneId ?? DBNull.Value);
                inv.ExecuteNonQuery();
                tx.Commit();
            }
        }
        catch
        {
            connection.Dispose();
            throw;
        }

        return new InvestigationStore(connection, path, info, time, batchSize);
    }

    public async ValueTask AddEvidenceAsync(Evidence evidence, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _evidence.Add(evidence);
            if (_evidence.Count >= _batchSize)
            {
                FlushLocked(null);
            }
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask AddCoverageAsync(SourceCoverage coverage, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(coverage);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _coverage.Add(coverage);
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask AddErrorAsync(string moduleId, ModuleError moduleError, CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(moduleId);
        ArgumentNullException.ThrowIfNull(moduleError);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _errors.Add((moduleId, moduleError));
        }
        finally
        {
            _gate.Release();
        }
    }

    public async ValueTask CheckpointAsync(ModuleResult result, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(result);

        // The runner passes CancellationToken.None; honour a token anyway only before taking the lock.
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            FlushLocked(result);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>
    /// Writes the correlation of this investigation in one durable transaction, after everything pending: objects
    /// and findings reference evidence that is already in the database.
    /// </summary>
    public async ValueTask AddCorrelationAsync(CorrelationResult result, long evidenceRead, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(result);
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            FlushLocked(null);
            if (!string.Equals(_synchronous, "FULL", StringComparison.Ordinal))
            {
                Execute(_connection, "PRAGMA synchronous = FULL;");
                _synchronous = "FULL";
            }

            using var tx = _connection.BeginTransaction();
            foreach (var o in result.Objects)
            {
                using var cmd = _connection.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = """
                    INSERT INTO CorrelatedObjects (ObjectId, InvestigationId, DisplayPath, NormalizedPath, FileName, Volume, MftEntry, MftSequence, Sha256,
                        OtherPaths, FirstUtcTicks, LastUtcTicks, SourceFamilies)
                    VALUES ($id, $inv, $display, $norm, $name, $vol, $entry, $seq, $sha, $other, $first, $last, $families);
                    """;
                cmd.Parameters.AddWithValue("$id", o.ObjectId.Value);
                cmd.Parameters.AddWithValue("$inv", o.InvestigationId.Value);
                cmd.Parameters.AddWithValue("$display", (object?)o.DisplayPath ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$norm", (object?)o.NormalizedPath ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$name", (object?)o.FileName ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$vol", (object?)o.Volume ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$entry", o.MftEntry is { } e ? (object)(long)e : DBNull.Value);
                cmd.Parameters.AddWithValue("$seq", o.MftSequence is { } q ? (object)(long)q : DBNull.Value);
                cmd.Parameters.AddWithValue("$sha", (object?)o.Sha256?.Hex ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$other", Rows.Strings(o.OtherPaths));
                cmd.Parameters.AddWithValue("$first", (object?)o.FirstUtc?.UtcTicks ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$last", (object?)o.LastUtc?.UtcTicks ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$families", Rows.Strings(o.SourceFamilies));
                cmd.ExecuteNonQuery();

                foreach (var m in o.Members)
                {
                    using var member = _connection.CreateCommand();
                    member.Transaction = tx;
                    member.CommandText = "INSERT INTO ObjectMembers (ObjectId, EvidenceId, Link) VALUES ($o, $e, $l);";
                    member.Parameters.AddWithValue("$o", o.ObjectId.Value);
                    member.Parameters.AddWithValue("$e", m.EvidenceId.Value);
                    member.Parameters.AddWithValue("$l", m.Link.ToString());
                    member.ExecuteNonQuery();
                }
            }

            foreach (var f in result.Findings)
            {
                using var cmd = _connection.CreateCommand();
                cmd.Transaction = tx;
                cmd.CommandText = """
                    INSERT INTO Findings (FindingId, InvestigationId, RuleId, Confidence, Title, Description, Rationale, Limitations,
                        FirstUtcTicks, LastUtcTicks, ObjectId, IndependentFamilies, VerifiedIdentification)
                    VALUES ($id, $inv, $rule, $conf, $title, $desc, $why, $lim, $first, $last, $obj, $families, $verified);
                    """;
                cmd.Parameters.AddWithValue("$id", f.FindingId.Value);
                cmd.Parameters.AddWithValue("$inv", f.InvestigationId.Value);
                cmd.Parameters.AddWithValue("$rule", f.RuleId);
                cmd.Parameters.AddWithValue("$conf", f.Confidence.ToString());
                cmd.Parameters.AddWithValue("$title", f.Title);
                cmd.Parameters.AddWithValue("$desc", f.Description);
                cmd.Parameters.AddWithValue("$why", f.Rationale);
                cmd.Parameters.AddWithValue("$lim", Rows.Limitations(f.Limitations));
                cmd.Parameters.AddWithValue("$first", (object?)f.FirstUtc?.UtcTicks ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$last", (object?)f.LastUtc?.UtcTicks ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$obj", (object?)f.ObjectId?.Value ?? DBNull.Value);
                cmd.Parameters.AddWithValue("$families", Rows.Strings(f.IndependentFamilies));
                cmd.Parameters.AddWithValue("$verified", f.VerifiedIdentification ? 1 : 0);
                cmd.ExecuteNonQuery();

                foreach (var m in f.Members)
                {
                    using var member = _connection.CreateCommand();
                    member.Transaction = tx;
                    member.CommandText = "INSERT INTO FindingMembers (FindingId, EvidenceId, Role) VALUES ($f, $e, $r);";
                    member.Parameters.AddWithValue("$f", f.FindingId.Value);
                    member.Parameters.AddWithValue("$e", m.EvidenceId.Value);
                    member.Parameters.AddWithValue("$r", m.Role);
                    member.ExecuteNonQuery();
                }
            }

            using (var run = _connection.CreateCommand())
            {
                run.Transaction = tx;
                run.CommandText = """
                    INSERT INTO CorrelationRuns (InvestigationId, CompletedUtcTicks, EvidenceRead, ObjectCount, FindingCount, Limitations)
                    VALUES ($inv, $done, $read, $objects, $findings, $lim);
                    """;
                run.Parameters.AddWithValue("$inv", Info.InvestigationId.Value);
                run.Parameters.AddWithValue("$done", _time.GetUtcNow().UtcTicks);
                run.Parameters.AddWithValue("$read", evidenceRead);
                run.Parameters.AddWithValue("$objects", result.Objects.Count);
                run.Parameters.AddWithValue("$findings", result.Findings.Count);
                run.Parameters.AddWithValue("$lim", Rows.Limitations(result.Limitations));
                run.ExecuteNonQuery();
            }

            tx.Commit();
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Writes a consistent copy of the database to a new file in the investigation folder.</summary>
    public void BackupTo(OutputSink sink, string relativePath)
    {
        ArgumentNullException.ThrowIfNull(sink);
        _gate.Wait();
        try
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            FlushLocked(null);
            var target = sink.ReserveNewFile(relativePath);
            using var destination = new SqliteConnection(new SqliteConnectionStringBuilder
            {
                DataSource = target,
                Mode = SqliteOpenMode.ReadWrite,
                Pooling = false,
            }.ToString());
            destination.Open();

            // No journal file for the copy: it is written once and never modified.
            Execute(destination, "PRAGMA journal_mode = OFF;");
            _connection.BackupDatabase(destination);
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Writes anything still pending and closes the database.</summary>
    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposeStarted, 1) == 1)
        {
            return;
        }

        _gate.Wait();
        try
        {
            FlushLocked(null);
        }
        finally
        {
            _disposed = true;
            _connection.Dispose();
            _gate.Release();
            _gate.Dispose();
        }
    }

    private void FlushLocked(ModuleResult? result)
    {
        if (_evidence.Count == 0 && _coverage.Count == 0 && _errors.Count == 0 && result is null)
        {
            return;
        }

        // Durability policy: a module checkpoint is forced to disk (FULL); intermediate batches, which only bound
        // memory, are handed to the OS without a forced flush (NORMAL). An application crash loses nothing that
        // was flushed; a power loss in the middle of a module may lose that module's unfinished part.
        var sync = result is null ? "NORMAL" : "FULL";
        if (!string.Equals(sync, _synchronous, StringComparison.Ordinal))
        {
            Execute(_connection, result is null ? "PRAGMA synchronous = NORMAL;" : "PRAGMA synchronous = FULL;");
            _synchronous = sync;
        }

        var started = System.Diagnostics.Stopwatch.GetTimestamp();
        using var tx = _connection.BeginTransaction();
        if (_evidence.Count > 0)
        {
            InsertEvidence(tx);
        }

        foreach (var c in _coverage)
        {
            using var cmd = _connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO SourceCoverage (InvestigationId, ModuleId, SourceKind, Scope, Status, EarliestUtcTicks, LatestUtcTicks, ItemsRead, Limitations)
                VALUES ($inv, $mod, $src, $scope, $status, $early, $late, $items, $lim);
                """;
            cmd.Parameters.AddWithValue("$inv", c.InvestigationId.Value);
            cmd.Parameters.AddWithValue("$mod", c.ModuleId);
            cmd.Parameters.AddWithValue("$src", c.Source.ToString());
            cmd.Parameters.AddWithValue("$scope", c.Scope);
            cmd.Parameters.AddWithValue("$status", c.Status.ToString());
            cmd.Parameters.AddWithValue("$early", (object?)c.EarliestUtc?.UtcTicks ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$late", (object?)c.LatestUtc?.UtcTicks ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$items", (object?)c.ItemsRead ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$lim", Rows.Limitations(c.Limitations));
            cmd.ExecuteNonQuery();
        }

        foreach (var (module, error) in _errors)
        {
            using var cmd = _connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "INSERT INTO ModuleErrors (InvestigationId, ModuleId, Message, ExceptionType, Location) VALUES ($inv, $mod, $msg, $type, $loc);";
            cmd.Parameters.AddWithValue("$inv", Info.InvestigationId.Value);
            cmd.Parameters.AddWithValue("$mod", module);
            cmd.Parameters.AddWithValue("$msg", error.Message);
            cmd.Parameters.AddWithValue("$type", (object?)error.ExceptionType ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$loc", (object?)error.Location ?? DBNull.Value);
            cmd.ExecuteNonQuery();
        }

        if (result is not null)
        {
            using var cmd = _connection.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO ModuleResults (InvestigationId, ModuleId, State, StartedUtcTicks, FinishedUtcTicks, EvidenceCount, CoverageCount, Reason, CheckpointUtcTicks)
                VALUES ($inv, $mod, $state, $start, $finish, $ev, $cov, $reason, $cp);
                """;
            cmd.Parameters.AddWithValue("$inv", Info.InvestigationId.Value);
            cmd.Parameters.AddWithValue("$mod", result.ModuleId);
            cmd.Parameters.AddWithValue("$state", result.State.ToString());
            cmd.Parameters.AddWithValue("$start", (object?)result.StartedUtc?.UtcTicks ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$finish", (object?)result.FinishedUtc?.UtcTicks ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$ev", result.EvidenceCount);
            cmd.Parameters.AddWithValue("$cov", result.CoverageCount);
            cmd.Parameters.AddWithValue("$reason", (object?)result.Reason ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$cp", _time.GetUtcNow().UtcTicks);
            cmd.ExecuteNonQuery();
        }

        var beforeCommit = System.Diagnostics.Stopwatch.GetTimestamp();
        tx.Commit();
        Stats.Record(_evidence.Count, System.Diagnostics.Stopwatch.GetElapsedTime(started, beforeCommit), System.Diagnostics.Stopwatch.GetElapsedTime(beforeCommit));

        // Only after a successful commit: a failed flush keeps everything pending for the next attempt.
        _evidence.Clear();
        _coverage.Clear();
        _errors.Clear();
    }

    private void InsertEvidence(SqliteTransaction tx)
    {
        using var cmd = _connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = """
            INSERT INTO Evidence (EvidenceId, InvestigationId, ModuleId, SchemaVersion, SourceKind, ArtifactPath, Parser, ParserVersion,
                Locator, EventType, TsUtcTicks, TsField, TsPrecision, TsSourceZone, TsUncertaintyTicks, OtherTimestamps,
                RecordedPath, NormalizedPath, FileName, VolumeSerial, MftEntry, MftSequence, Size, ObjectSha256, ArtifactSha256,
                Confidence, Rationale, CollectionStatus, Description, Limitations, UserSid, Attributes, CollectedAtUtcTicks)
            VALUES ($id, $inv, $mod, $schema, $src, $artifact, $parser, $parserVer,
                $loc, $event, $ts, $tsField, $tsPrec, $tsZone, $tsUnc, $other,
                $recorded, $normalized, $name, $serial, $entry, $seq, $size, $objHash, $artHash,
                $conf, $why, $status, $desc, $lim, $sid, $attrs, $collected);
            """;
        string[] names =
        [
            "$id", "$inv", "$mod", "$schema", "$src", "$artifact", "$parser", "$parserVer", "$loc", "$event", "$ts", "$tsField",
            "$tsPrec", "$tsZone", "$tsUnc", "$other", "$recorded", "$normalized", "$name", "$serial", "$entry", "$seq", "$size",
            "$objHash", "$artHash", "$conf", "$why", "$status", "$desc", "$lim", "$sid", "$attrs", "$collected",
        ];
        var p = new Dictionary<string, SqliteParameter>(StringComparer.Ordinal);
        foreach (var n in names)
        {
            // No fixed SqliteType: the type is inferred from each value, so integers stay integers.
            var param = cmd.CreateParameter();
            param.ParameterName = n;
            cmd.Parameters.Add(param);
            p[n] = param;
        }

        cmd.Prepare();

        foreach (var e in _evidence)
        {
            static object Db(object? v) => v ?? DBNull.Value;
            p["$id"].Value = e.EvidenceId.Value;
            p["$inv"].Value = e.InvestigationId.Value;
            p["$mod"].Value = e.ModuleId;
            p["$schema"].Value = Evidence.SchemaVersion;
            p["$src"].Value = e.Source.Kind.ToString();
            p["$artifact"].Value = e.Source.ArtifactPath;
            p["$parser"].Value = e.Source.Parser;
            p["$parserVer"].Value = e.Source.ParserVersion;
            p["$loc"].Value = e.Locator;
            p["$event"].Value = e.EventType.ToString();
            p["$ts"].Value = Db(e.Timestamp?.ValueUtc.UtcTicks);
            p["$tsField"].Value = Db(e.Timestamp?.Field);
            p["$tsPrec"].Value = Db(e.Timestamp?.Precision.ToString());
            p["$tsZone"].Value = Db(e.Timestamp?.SourceTimeZone);
            p["$tsUnc"].Value = Db(e.Timestamp?.Uncertainty.Ticks);
            p["$other"].Value = Rows.Timestamps(e.OtherTimestamps);
            p["$recorded"].Value = Db(e.Target.RecordedPath);
            p["$normalized"].Value = Db(e.Target.NormalizedPath);
            p["$name"].Value = Db(e.Target.FileName);
            p["$serial"].Value = Db(Rows.Serial(e.Target.VolumeSerial));
            p["$entry"].Value = Db(e.Target.MftEntry is { } m ? (long)m : null);
            p["$seq"].Value = Db(e.Target.MftSequence is { } s ? (long)s : null);
            p["$size"].Value = Db(e.Target.Size);
            p["$objHash"].Value = Db(e.ObjectSha256?.Hex);
            p["$artHash"].Value = Db(e.ArtifactSha256?.Hex);
            p["$conf"].Value = e.Confidence.ToString();
            p["$why"].Value = e.Rationale;
            p["$status"].Value = e.CollectionStatus.ToString();
            p["$desc"].Value = e.Description;
            p["$lim"].Value = Rows.Limitations(e.Limitations);
            p["$sid"].Value = Db(e.UserSid);
            p["$attrs"].Value = Rows.Attributes(e.Attributes);
            p["$collected"].Value = e.CollectedAtUtc.UtcTicks;
            cmd.ExecuteNonQuery();
        }
    }

    [System.Diagnostics.CodeAnalysis.SuppressMessage("Security", "CA2100:Review SQL queries for security vulnerabilities", Justification = "Only constant schema and PRAGMA text from this class is executed.")]
    private static void Execute(SqliteConnection connection, string sql, SqliteTransaction? tx = null)
    {
        using var cmd = connection.CreateCommand();
        cmd.Transaction = tx;
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }
}

/// <summary>Counters of written batches: how long inserting and committing took.</summary>
public sealed class StoreStatistics
{
    public int Transactions { get; private set; }

    public long RecordsWritten { get; private set; }

    public TimeSpan InsertTime { get; private set; }

    public TimeSpan CommitTime { get; private set; }

    internal void Record(int records, TimeSpan insert, TimeSpan commit)
    {
        Transactions++;
        RecordsWritten += records;
        InsertTime += insert;
        CommitTime += commit;
    }

    public override string ToString() =>
        $"{Transactions} transactions, {RecordsWritten} records, insert {InsertTime.TotalSeconds:F1} s, commit {CommitTime.TotalSeconds:F1} s";
}
