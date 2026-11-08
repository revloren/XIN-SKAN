using System.Collections.Frozen;

namespace XINSkan.Core.Permissions;

/// <summary>Result of probing one capability. A missing capability always carries the reason.</summary>
public sealed record CapabilityState(Capability Capability, bool Available, string Reason);

/// <summary>A consent given by the device owner: who, when, and the exact statement they agreed to.</summary>
public sealed record ConsentRecord(Consent Consent, string GrantedBy, DateTimeOffset GrantedAtUtc, string Statement);

/// <summary>Probes the operating system for a capability. Implemented per platform; tests use fakes.</summary>
public interface ICapabilityProbe
{
    CapabilityState Probe(Capability capability);
}

/// <summary>What an analyzer needs. Missing required items skip the module; missing optional items degrade it.</summary>
public sealed record AnalyzerRequirements
{
    public static readonly AnalyzerRequirements None = new();

    public IReadOnlyList<Capability> RequiredCapabilities { get; init; } = [];

    public IReadOnlyList<Capability> OptionalCapabilities { get; init; } = [];

    public IReadOnlyList<Consent> RequiredConsents { get; init; } = [];
}

/// <summary>Immutable view of capabilities and consents for one investigation.</summary>
public sealed class PermissionSnapshot
{
    private readonly FrozenDictionary<Capability, CapabilityState> _capabilities;
    private readonly FrozenDictionary<Consent, ConsentRecord> _consents;

    internal PermissionSnapshot(IEnumerable<CapabilityState> capabilities, IEnumerable<ConsentRecord> consents)
    {
        _capabilities = capabilities.ToFrozenDictionary(c => c.Capability);
        _consents = consents.ToFrozenDictionary(c => c.Consent);
    }

    public IReadOnlyCollection<CapabilityState> Capabilities => _capabilities.Values;

    public IReadOnlyCollection<ConsentRecord> Consents => _consents.Values;

    public bool Has(Capability capability) => _capabilities.TryGetValue(capability, out var s) && s.Available;

    public bool Has(Consent consent) => _consents.ContainsKey(consent);

    public CapabilityState Get(Capability capability) =>
        _capabilities.TryGetValue(capability, out var s) ? s : new CapabilityState(capability, false, "Not probed.");

    /// <summary>Why the requirements are not met, or null when they are.</summary>
    public string? Unmet(AnalyzerRequirements requirements)
    {
        ArgumentNullException.ThrowIfNull(requirements);
        var reasons = new List<string>();
        foreach (var c in requirements.RequiredCapabilities)
        {
            var state = Get(c);
            if (!state.Available)
            {
                reasons.Add($"{c}: {state.Reason}");
            }
        }

        foreach (var c in requirements.RequiredConsents)
        {
            if (!Has(c))
            {
                reasons.Add($"Consent {c} was not given.");
            }
        }

        return reasons.Count == 0 ? null : string.Join(" ", reasons);
    }

    /// <summary>Optional capabilities that are missing, with reasons; the analyzer must record these as limitations.</summary>
    public IReadOnlyList<CapabilityState> MissingOptional(AnalyzerRequirements requirements)
    {
        ArgumentNullException.ThrowIfNull(requirements);
        return requirements.OptionalCapabilities.Select(Get).Where(s => !s.Available).ToList();
    }
}

/// <summary>
/// Probes every capability once and holds the owner's consents. Consent is opt-in only: nothing is granted
/// by default and a consent cannot be granted without the statement shown to the owner.
/// </summary>
public sealed class PermissionManager
{
    private readonly ICapabilityProbe _probe;
    private readonly TimeProvider _time;
    private readonly Dictionary<Consent, ConsentRecord> _consents = [];

    public PermissionManager(ICapabilityProbe probe, TimeProvider time)
    {
        _probe = probe ?? throw new ArgumentNullException(nameof(probe));
        _time = time ?? throw new ArgumentNullException(nameof(time));
    }

    public ConsentRecord Grant(Consent consent, string grantedBy, string statement)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(grantedBy);
        ArgumentException.ThrowIfNullOrWhiteSpace(statement);
        var record = new ConsentRecord(consent, grantedBy, _time.GetUtcNow(), statement);
        _consents[consent] = record;
        return record;
    }

    public void Revoke(Consent consent) => _consents.Remove(consent);

    public PermissionSnapshot Snapshot()
    {
        var states = new List<CapabilityState>();
        foreach (var c in Enum.GetValues<Capability>())
        {
            CapabilityState state;
            try
            {
                state = _probe.Probe(c);
            }
#pragma warning disable CA1031 // A failing probe must not stop the investigation; it is reported as unavailable.
            catch (Exception ex)
#pragma warning restore CA1031
            {
                state = new CapabilityState(c, false, $"Probe failed: {ex.GetType().Name}: {ex.Message}");
            }

            states.Add(state with { Capability = c });
        }

        return new PermissionSnapshot(states, _consents.Values.ToList());
    }
}
