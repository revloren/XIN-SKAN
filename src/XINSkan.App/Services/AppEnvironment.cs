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

    public string SystemDrive { get; } = (Environment.GetEnvironmentVariable("SystemDrive") ?? "C:")[..2];

    public OutputLocationAssessment AssessOutput() => OutputLocationPolicy.Assess(OutputRoot, [SystemDrive + "\\"]);

    /// <summary>Probes capabilities on a background thread; every row comes from the live system.</summary>
    public static Task<PermissionSnapshot> ProbeAsync() =>
        Task.Run(() => new PermissionManager(new WindowsCapabilityProbe(), TimeProvider.System).Snapshot());
}
