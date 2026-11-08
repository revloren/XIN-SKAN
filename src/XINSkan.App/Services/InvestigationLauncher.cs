using System.Reflection;
using XINSkan.Analyzers.FileHunter;
using XINSkan.Core.Pipeline;
using XINSkan.Investigation;
using XINSkan.Storage;

namespace XINSkan.App.Services;

/// <summary>Starts a real investigation on this computer with the same composition as the command line.</summary>
public static class InvestigationLauncher
{
    public static string ToolVersion =>
        typeof(InvestigationLauncher).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "unknown";

    public static Task<InvestigationOutcome> RunAsync(string outputRoot, string? operatorName, IProgress<ModuleProgress> progress, CancellationToken cancellationToken)
    {
        var service = new InvestigationService(
            PlatformServices.ForWindows(),
            (sink, info) => InvestigationStore.Create(sink, info, TimeProvider.System),
            TimeProvider.System,
            ToolVersion);

        var request = new InvestigationRequest
        {
            OutputRoot = outputRoot,
            FileHunter = FileHunterOptions.ForCurrentSystem(),
            Operator = operatorName,
        };

        // The scan runs on the thread pool; progress is posted back by the caller's Progress<T>.
        return Task.Run(() => service.RunAsync(request, progress, cancellationToken), CancellationToken.None);
    }
}
