namespace XINSkan.Models;

/// <summary>Where an evidence record came from: the source kind, the artifact, and which parser read it.</summary>
public sealed record SourceRef
{
    public SourceRef(EvidenceSourceKind kind, string artifactPath, string parser, string parserVersion)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(artifactPath);
        ArgumentException.ThrowIfNullOrWhiteSpace(parser);
        ArgumentException.ThrowIfNullOrWhiteSpace(parserVersion);
        Kind = kind;
        ArtifactPath = artifactPath;
        Parser = parser;
        ParserVersion = parserVersion;
    }

    public EvidenceSourceKind Kind { get; }

    /// <summary>The artifact read, for example "\\.\C:\$MFT" or "C:\Windows\Prefetch\JAVAW.EXE-1234ABCD.pf".</summary>
    public string ArtifactPath { get; }

    public string Parser { get; }

    public string ParserVersion { get; }
}
