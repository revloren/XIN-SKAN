using System.IO;
using XINSkan.Core.Permissions;
using XINSkan.Platform.Windows;
using XINSkan.Security;

namespace XINSkan.App.Services;

/// <summary>
/// Settings for this run. Kept in memory on purpose: writing a settings file would change the investigated
/// computer. The default output folder sits next to the program, so XIN SKAN run from a USB drive writes there.
/// </summary>
public sealed class AppEnvironment
{
    private string _outputRoot = Path.Combine(AppContext.BaseDirectory, "Investigations");

    public event EventHandler? Changed;

    public string OutputRoot
    {
        get => _outputRoot;
        set
        {
            if (!string.Equals(_outputRoot, value, StringComparison.OrdinalIgnoreCase))
            {
                _outputRoot = value;
                Changed?.Invoke(this, EventArgs.Empty);
            }
        }
    }

    /// <summary>Tells the screens that read the output folder that a new investigation was written there.</summary>
    public void NotifyInvestigationsChanged() => Changed?.Invoke(this, EventArgs.Empty);

    public string SystemDrive { get; } = (Environment.GetEnvironmentVariable("SystemDrive") ?? "C:")[..2];

    /// <summary>Where results would go, in the operator's language. The policy itself lives in XINSkan.Security.</summary>
    public (bool OnInvestigatedVolume, string Text) DescribeOutput(string folder)
    {
        var a = OutputLocationPolicy.Assess(folder, [SystemDrive + "\\"]);
        var root = Path.GetPathRoot(Path.GetFullPath(folder));
        return (a.OnInvestigatedVolume, a.OnInvestigatedVolume
            ? $"Результаты будут записаны на диск {root}, который исследуется. Новые файлы могут занять место, где ещё лежат остатки удалённых файлов, и появятся в его журнале изменений."
            : $"Результаты будут записаны на диск {root}, который не исследуется.");
    }

    /// <summary>Probes capabilities on a background thread; every row comes from the live system.</summary>
    public static Task<PermissionSnapshot> ProbeAsync() =>
        Task.Run(() => new PermissionManager(new WindowsCapabilityProbe(), TimeProvider.System).Snapshot());
}
