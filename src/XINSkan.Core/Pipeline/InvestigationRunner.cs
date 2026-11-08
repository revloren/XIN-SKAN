using System.Text.RegularExpressions;
using XINSkan.Core.Permissions;
using XINSkan.Models;

namespace XINSkan.Core.Pipeline;

/// <summary>
/// Runs analyzers one after another. Each module is isolated: a module that throws is marked Failed and the
/// next one still runs; a module whose requirements are not met is Skipped with the reason. After every module
/// the sink checkpoints, so cancellation or a later failure never loses records already collected.
/// </summary>
public sealed partial class InvestigationRunner
{
    private readonly IInvestigationSink _sink;
    private readonly PermissionSnapshot _permissions;
    private readonly TimeProvider _time;
    private readonly IProgress<ModuleProgress> _progress;

    public InvestigationRunner(
        IInvestigationSink sink,
        PermissionSnapshot permissions,
        TimeProvider time,
        IProgress<ModuleProgress>? progress = null)
    {
        _sink = sink ?? throw new ArgumentNullException(nameof(sink));
        _permissions = permissions ?? throw new ArgumentNullException(nameof(permissions));
        _time = time ?? throw new ArgumentNullException(nameof(time));
        _progress = progress ?? new Progress<ModuleProgress>();
    }

    /// <remarks>
    /// A failure of the sink itself (storage unavailable) is not isolated: it is rethrown, because the
    /// investigation can no longer guarantee that what it reports was saved.
    /// </remarks>
    public async Task<InvestigationRunResult> RunAsync(
        Ulid investigationId,
        IReadOnlyList<IAnalyzer> analyzers,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(analyzers);
        if (investigationId.IsEmpty)
        {
            throw new ArgumentException("Investigation ID is empty.", nameof(investigationId));
        }

        ValidateIds(analyzers);

        var started = _time.GetUtcNow();
        var results = new List<ModuleResult>(analyzers.Count);
        var cancelled = false;

        foreach (var analyzer in analyzers)
        {
            ModuleResult result;
            if (cancellationToken.IsCancellationRequested)
            {
                cancelled = true;
                result = new ModuleResult
                {
                    ModuleId = analyzer.Id,
                    State = ModuleState.Cancelled,
                    Reason = "The investigation was cancelled before this module started.",
                };
            }
            else if (_permissions.Unmet(analyzer.Requirements) is { } unmet)
            {
                result = new ModuleResult
                {
                    ModuleId = analyzer.Id,
                    State = ModuleState.Skipped,
                    Reason = unmet,
                };
            }
            else
            {
                result = await RunModuleAsync(investigationId, analyzer, cancellationToken).ConfigureAwait(false);
                cancelled |= result.State == ModuleState.Cancelled;
            }

            // Never pass the investigation token here: a cancelled investigation must still save its records.
            await _sink.CheckpointAsync(result, CancellationToken.None).ConfigureAwait(false);
            results.Add(result);
            _progress.Report(new ModuleProgress(analyzer.Id, result.State, result.Reason));
        }

        return new InvestigationRunResult(investigationId, started, _time.GetUtcNow(), cancelled, results);
    }

    private async Task<ModuleResult> RunModuleAsync(Ulid investigationId, IAnalyzer analyzer, CancellationToken cancellationToken)
    {
        var writer = new ModuleEvidenceWriter(_sink, investigationId, analyzer.Id);
        var context = new AnalyzerContext(investigationId, analyzer.Id, writer, _permissions, _time, _progress);
        var start = _time.GetUtcNow();
        _progress.Report(new ModuleProgress(analyzer.Id, ModuleState.Running));

        ModuleState state;
        string? reason = null;
        var errors = new List<ModuleError>();
        try
        {
            await analyzer.RunAsync(context, cancellationToken).ConfigureAwait(false);
            state = writer.Errors.Count > 0 ? ModuleState.CompletedWithErrors : ModuleState.Completed;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            state = ModuleState.Cancelled;
            reason = "Cancelled by the operator; records collected before cancellation are kept.";
        }
        catch (InvalidEvidenceException ex)
        {
            state = ModuleState.Failed;
            reason = "The module produced a record that violates the evidence schema and was stopped.";
            errors.Add(new ModuleError(ex.Message, nameof(InvalidEvidenceException)));
        }
#pragma warning disable CA1031 // Module isolation: any analyzer failure is recorded and the investigation continues.
        catch (Exception ex)
#pragma warning restore CA1031
        {
            state = ModuleState.Failed;
            reason = $"The module stopped with an unexpected error: {ex.GetType().Name}.";
            errors.Add(new ModuleError(ex.Message, ex.GetType().FullName, ex.TargetSite?.ToString()));
        }
        finally
        {
            writer.Close();
        }

        return new ModuleResult
        {
            ModuleId = analyzer.Id,
            State = state,
            StartedUtc = start,
            FinishedUtc = _time.GetUtcNow(),
            EvidenceCount = writer.EvidenceCount,
            CoverageCount = writer.CoverageCount,
            Errors = [.. writer.Errors, .. errors],
            Reason = reason,
        };
    }

    private static void ValidateIds(IReadOnlyList<IAnalyzer> analyzers)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var a in analyzers)
        {
            ArgumentNullException.ThrowIfNull(a);
            if (a.Id is null || !ModuleIdPattern().IsMatch(a.Id))
            {
                throw new ArgumentException($"Module ID '{a.Id}' must be lowercase letters, digits and hyphens.", nameof(analyzers));
            }

            if (!seen.Add(a.Id))
            {
                throw new ArgumentException($"Module ID '{a.Id}' appears twice.", nameof(analyzers));
            }
        }
    }

    [GeneratedRegex("^[a-z][a-z0-9-]{1,63}$", RegexOptions.CultureInvariant)]
    private static partial Regex ModuleIdPattern();
}
