namespace XINSkan.Storage;

/// <summary>
/// Schema of the investigation database. Evidence, coverage, module results and errors are append-only:
/// triggers abort every UPDATE and DELETE, so even a bug in XIN SKAN cannot rewrite what was collected.
/// </summary>
/// <remarks>
/// The specification's FileEvents and ExecutionEvents tables are views over Evidence filtered by event type,
/// so each fact is stored once. Version 2 (stage 7) adds the correlation tables, version 3 (stage 9) the signature
/// match columns of Findings and the SignatureDatabases table; network and report tables are added by the stages
/// that produce them (see docs/STORAGE.md).
/// </remarks>
internal static class Schema
{
    public const int Version = 3;

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

        CREATE TABLE CorrelationRuns (
            Id              INTEGER PRIMARY KEY AUTOINCREMENT,
            InvestigationId TEXT NOT NULL REFERENCES Investigations(InvestigationId),
            CompletedUtcTicks INTEGER NOT NULL,
            EvidenceRead    INTEGER NOT NULL,
            ObjectCount     INTEGER NOT NULL,
            FindingCount    INTEGER NOT NULL,
            Limitations     TEXT NOT NULL
        );

        CREATE TABLE CorrelatedObjects (
            ObjectId        TEXT PRIMARY KEY,
            InvestigationId TEXT NOT NULL REFERENCES Investigations(InvestigationId),
            DisplayPath     TEXT,
            NormalizedPath  TEXT,
            FileName        TEXT,
            Volume          TEXT,
            MftEntry        INTEGER,
            MftSequence     INTEGER,
            Sha256          TEXT,
            OtherPaths      TEXT NOT NULL,
            FirstUtcTicks   INTEGER,
            LastUtcTicks    INTEGER,
            SourceFamilies  TEXT NOT NULL
        );

        CREATE TABLE ObjectMembers (
            ObjectId        TEXT NOT NULL REFERENCES CorrelatedObjects(ObjectId),
            EvidenceId      TEXT NOT NULL REFERENCES Evidence(EvidenceId),
            Link            TEXT NOT NULL,
            PRIMARY KEY (ObjectId, EvidenceId)
        );

        CREATE TABLE Findings (
            FindingId       TEXT PRIMARY KEY,
            InvestigationId TEXT NOT NULL REFERENCES Investigations(InvestigationId),
            RuleId          TEXT NOT NULL,
            Confidence      TEXT NOT NULL,
            Title           TEXT NOT NULL,
            Description     TEXT NOT NULL,
            Rationale       TEXT NOT NULL,
            Limitations     TEXT NOT NULL,
            FirstUtcTicks   INTEGER,
            LastUtcTicks    INTEGER,
            ObjectId        TEXT REFERENCES CorrelatedObjects(ObjectId),
            IndependentFamilies TEXT NOT NULL,
            VerifiedIdentification INTEGER NOT NULL,
            MatchKind       TEXT,
            ClientId        TEXT
        );

        CREATE TABLE SignatureDatabases (
            Id              INTEGER PRIMARY KEY AUTOINCREMENT,
            InvestigationId TEXT NOT NULL REFERENCES Investigations(InvestigationId),
            Version         TEXT NOT NULL,
            Origin          TEXT NOT NULL,
            ManifestSha256  TEXT NOT NULL,
            KeyId           TEXT,
            Clients         INTEGER NOT NULL,
            VerifiedClients INTEGER NOT NULL,
            Hashes          INTEGER NOT NULL,
            Problems        TEXT NOT NULL
        );

        CREATE TABLE FindingMembers (
            FindingId       TEXT NOT NULL REFERENCES Findings(FindingId),
            EvidenceId      TEXT NOT NULL REFERENCES Evidence(EvidenceId),
            Role            TEXT NOT NULL,
            PRIMARY KEY (FindingId, EvidenceId)
        );

        CREATE INDEX IX_ObjectMembers_Evidence  ON ObjectMembers(EvidenceId);
        CREATE INDEX IX_FindingMembers_Evidence ON FindingMembers(EvidenceId);
        CREATE INDEX IX_Findings_Rule           ON Findings(RuleId);

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
        CREATE TRIGGER CorrelationRuns_NoUpdate BEFORE UPDATE ON CorrelationRuns
            BEGIN SELECT RAISE(ABORT, 'Correlation is immutable'); END;
        CREATE TRIGGER CorrelationRuns_NoDelete BEFORE DELETE ON CorrelationRuns
            BEGIN SELECT RAISE(ABORT, 'Correlation is immutable'); END;
        CREATE TRIGGER CorrelatedObjects_NoUpdate BEFORE UPDATE ON CorrelatedObjects
            BEGIN SELECT RAISE(ABORT, 'Correlation is immutable'); END;
        CREATE TRIGGER CorrelatedObjects_NoDelete BEFORE DELETE ON CorrelatedObjects
            BEGIN SELECT RAISE(ABORT, 'Correlation is immutable'); END;
        CREATE TRIGGER ObjectMembers_NoUpdate BEFORE UPDATE ON ObjectMembers
            BEGIN SELECT RAISE(ABORT, 'Correlation is immutable'); END;
        CREATE TRIGGER ObjectMembers_NoDelete BEFORE DELETE ON ObjectMembers
            BEGIN SELECT RAISE(ABORT, 'Correlation is immutable'); END;
        CREATE TRIGGER Findings_NoUpdate BEFORE UPDATE ON Findings
            BEGIN SELECT RAISE(ABORT, 'Correlation is immutable'); END;
        CREATE TRIGGER Findings_NoDelete BEFORE DELETE ON Findings
            BEGIN SELECT RAISE(ABORT, 'Correlation is immutable'); END;
        CREATE TRIGGER FindingMembers_NoUpdate BEFORE UPDATE ON FindingMembers
            BEGIN SELECT RAISE(ABORT, 'Correlation is immutable'); END;
        CREATE TRIGGER FindingMembers_NoDelete BEFORE DELETE ON FindingMembers
            BEGIN SELECT RAISE(ABORT, 'Correlation is immutable'); END;
        CREATE TRIGGER SignatureDatabases_NoUpdate BEFORE UPDATE ON SignatureDatabases
            BEGIN SELECT RAISE(ABORT, 'Correlation is immutable'); END;
        CREATE TRIGGER SignatureDatabases_NoDelete BEFORE DELETE ON SignatureDatabases
            BEGIN SELECT RAISE(ABORT, 'Correlation is immutable'); END;
        CREATE TRIGGER Investigations_NoUpdate BEFORE UPDATE ON Investigations
            BEGIN SELECT RAISE(ABORT, 'Investigation header is immutable'); END;
        CREATE TRIGGER Investigations_NoDelete BEFORE DELETE ON Investigations
            BEGIN SELECT RAISE(ABORT, 'Investigation header is immutable'); END;
        """;
}
