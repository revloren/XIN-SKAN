namespace XINSkan.Storage;

/// <summary>
/// Schema of the investigation database. Evidence, coverage, module results and errors are append-only:
/// triggers abort every UPDATE and DELETE, so even a bug in XIN SKAN cannot rewrite what was collected.
/// </summary>
/// <remarks>
/// The specification's FileEvents and ExecutionEvents tables are views over Evidence filtered by event type,
/// so each fact is stored once. Network, signature, correlation and report tables are added by the stages
/// that produce them (see docs/STORAGE.md).
/// </remarks>
internal static class Schema
{
    public const int Version = 1;

    public const string Create = """
        PRAGMA foreign_keys = ON;

        CREATE TABLE SchemaInfo (
            Version         INTEGER NOT NULL,
            CreatedUtc      TEXT    NOT NULL
        );

        CREATE TABLE Investigations (
            InvestigationId TEXT PRIMARY KEY,
            StartedUtc      TEXT NOT NULL,
            ToolVersion     TEXT NOT NULL,
            Operator        TEXT,
            MachineName     TEXT,
            OsDescription   TEXT,
            TimeZoneId      TEXT
        );

        CREATE TABLE Evidence (
            EvidenceId          TEXT PRIMARY KEY,
            InvestigationId     TEXT NOT NULL REFERENCES Investigations(InvestigationId),
            ModuleId            TEXT NOT NULL,
            SchemaVersion       INTEGER NOT NULL,
            SourceKind          TEXT NOT NULL,
            ArtifactPath        TEXT NOT NULL,
            Parser              TEXT NOT NULL,
            ParserVersion       TEXT NOT NULL,
            Locator             TEXT NOT NULL,
            EventType           TEXT NOT NULL,
            TsUtcTicks          INTEGER,
            TsField             TEXT,
            TsPrecision         TEXT,
            TsSourceZone        TEXT,
            TsUncertaintyTicks  INTEGER,
            OtherTimestamps     TEXT NOT NULL,
            RecordedPath        TEXT,
            NormalizedPath      TEXT,
            FileName            TEXT,
            VolumeSerial        TEXT,
            MftEntry            INTEGER,
            MftSequence         INTEGER,
            Size                INTEGER,
            ObjectSha256        TEXT,
            ArtifactSha256      TEXT,
            Confidence          TEXT NOT NULL,
            Rationale           TEXT NOT NULL,
            CollectionStatus    TEXT NOT NULL,
            Description         TEXT NOT NULL,
            Limitations         TEXT NOT NULL,
            UserSid             TEXT,
            Attributes          TEXT NOT NULL,
            CollectedAtUtcTicks INTEGER NOT NULL
        );

        CREATE INDEX IX_Evidence_NormalizedPath ON Evidence(NormalizedPath);
        CREATE INDEX IX_Evidence_FileName       ON Evidence(FileName);
        CREATE INDEX IX_Evidence_Mft            ON Evidence(MftEntry, MftSequence);
        CREATE INDEX IX_Evidence_Time           ON Evidence(TsUtcTicks);
        CREATE INDEX IX_Evidence_Module         ON Evidence(ModuleId);
        CREATE INDEX IX_Evidence_ObjectSha256   ON Evidence(ObjectSha256);

        CREATE TABLE SourceCoverage (
            Id              INTEGER PRIMARY KEY AUTOINCREMENT,
            InvestigationId TEXT NOT NULL REFERENCES Investigations(InvestigationId),
            ModuleId        TEXT NOT NULL,
            SourceKind      TEXT NOT NULL,
            Scope           TEXT NOT NULL,
            Status          TEXT NOT NULL,
            EarliestUtcTicks INTEGER,
            LatestUtcTicks  INTEGER,
            ItemsRead       INTEGER,
            Limitations     TEXT NOT NULL
        );

        CREATE TABLE ModuleResults (
            Id              INTEGER PRIMARY KEY AUTOINCREMENT,
            InvestigationId TEXT NOT NULL REFERENCES Investigations(InvestigationId),
            ModuleId        TEXT NOT NULL,
            State           TEXT NOT NULL,
            StartedUtcTicks INTEGER,
            FinishedUtcTicks INTEGER,
            EvidenceCount   INTEGER NOT NULL,
            CoverageCount   INTEGER NOT NULL,
            Reason          TEXT,
            CheckpointUtcTicks INTEGER NOT NULL
        );

        CREATE TABLE ModuleErrors (
            Id              INTEGER PRIMARY KEY AUTOINCREMENT,
            InvestigationId TEXT NOT NULL REFERENCES Investigations(InvestigationId),
            ModuleId        TEXT NOT NULL,
            Message         TEXT NOT NULL,
            ExceptionType   TEXT,
            Location        TEXT
        );

        CREATE VIEW FileEvents AS
            SELECT * FROM Evidence
            WHERE EventType IN ('Existed', 'Created', 'Modified', 'Renamed', 'Moved', 'Deleted', 'Accessed', 'Downloaded');

        CREATE VIEW ExecutionEvents AS
            SELECT * FROM Evidence
            WHERE EventType IN ('Executed', 'ExecutedLikely', 'Loaded');

        CREATE TRIGGER Evidence_NoUpdate BEFORE UPDATE ON Evidence
            BEGIN SELECT RAISE(ABORT, 'Evidence is immutable'); END;
        CREATE TRIGGER Evidence_NoDelete BEFORE DELETE ON Evidence
            BEGIN SELECT RAISE(ABORT, 'Evidence is immutable'); END;
        CREATE TRIGGER SourceCoverage_NoUpdate BEFORE UPDATE ON SourceCoverage
            BEGIN SELECT RAISE(ABORT, 'Coverage is immutable'); END;
        CREATE TRIGGER SourceCoverage_NoDelete BEFORE DELETE ON SourceCoverage
            BEGIN SELECT RAISE(ABORT, 'Coverage is immutable'); END;
        CREATE TRIGGER ModuleResults_NoUpdate BEFORE UPDATE ON ModuleResults
            BEGIN SELECT RAISE(ABORT, 'Module results are immutable'); END;
        CREATE TRIGGER ModuleResults_NoDelete BEFORE DELETE ON ModuleResults
            BEGIN SELECT RAISE(ABORT, 'Module results are immutable'); END;
        CREATE TRIGGER ModuleErrors_NoUpdate BEFORE UPDATE ON ModuleErrors
            BEGIN SELECT RAISE(ABORT, 'Module errors are immutable'); END;
        CREATE TRIGGER ModuleErrors_NoDelete BEFORE DELETE ON ModuleErrors
            BEGIN SELECT RAISE(ABORT, 'Module errors are immutable'); END;
        CREATE TRIGGER Investigations_NoUpdate BEFORE UPDATE ON Investigations
            BEGIN SELECT RAISE(ABORT, 'Investigation header is immutable'); END;
        CREATE TRIGGER Investigations_NoDelete BEFORE DELETE ON Investigations
            BEGIN SELECT RAISE(ABORT, 'Investigation header is immutable'); END;
        """;
}
