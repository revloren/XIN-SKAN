// Discovers [Fact]/[Theory] methods in the compiled test sources and runs them. Exit code 1 on any failure.
using System.Diagnostics;
using System.Reflection;
using Xunit;

var filter = args.Length > 0 ? args[0] : null;
var asm = typeof(OfflineRunnerMarker).Assembly;
int passed = 0, failed = 0, skipped = 0;
var sw = Stopwatch.StartNew();

foreach (var type in asm.GetTypes().Where(t => t.IsClass && !t.IsAbstract && t.Namespace?.StartsWith("XINSkan", StringComparison.Ordinal) == true).OrderBy(t => t.FullName))
{
    foreach (var m in type.GetMethods(BindingFlags.Public | BindingFlags.Instance).Where(m => m.GetCustomAttribute<FactAttribute>() is not null).OrderBy(m => m.Name))
    {
        var name = $"{type.Name}.{m.Name}";
        if (filter is not null && !name.Contains(filter, StringComparison.OrdinalIgnoreCase)) continue;
        if (m.GetCustomAttribute<FactAttribute>()!.Skip is { } skip) { skipped++; Console.WriteLine($"SKIP {name}: {skip}"); continue; }

        var rows = m.GetCustomAttributes<InlineDataAttribute>().Select(d => d.Data).ToList();
        if (rows.Count == 0) rows.Add([]);
        foreach (var row in rows)
        {
            var label = row.Length == 0 ? name : $"{name}({string.Join(", ", row.Select(r => r ?? "null"))})";
            object? instance = null;
            try
            {
                var ctor = type.GetConstructors().OrderBy(c => c.GetParameters().Length).First();
                instance = ctor.GetParameters().Length == 0 ? ctor.Invoke(null) : ctor.Invoke([new ConsoleOutput()]);
                var ps = m.GetParameters();
                var call = ps.Select((p, i) => ConvertArg(i < row.Length ? row[i] : null, p.ParameterType)).ToArray();
                var ret = m.Invoke(instance, call);
                if (ret is Task t) await t;
                passed++;
            }
            catch (Exception ex)
            {
                var e = ex is TargetInvocationException tie ? tie.InnerException! : ex;
                failed++;
                Console.WriteLine($"FAIL {label}\n     {e.GetType().Name}: {e.Message}\n     {e.StackTrace?.Split('\n').FirstOrDefault(l => l.Contains("XINSkan", StringComparison.Ordinal))?.Trim()}");
            }
            finally
            {
                if (instance is IAsyncDisposable ad) await ad.DisposeAsync();
                else if (instance is IDisposable d) d.Dispose();
            }
        }
    }
}

Console.WriteLine($"passed={passed} failed={failed} skipped={skipped} seconds={sw.Elapsed.TotalSeconds:F1}");
return failed == 0 ? 0 : 1;

static object? ConvertArg(object? value, Type target)
{
    if (value is null) return null;
    var t = Nullable.GetUnderlyingType(target) ?? target;
    if (t.IsInstanceOfType(value)) return value;
    if (t.IsEnum) return Enum.ToObject(t, value);
    return System.Convert.ChangeType(value, t, System.Globalization.CultureInfo.InvariantCulture);
}

internal sealed class OfflineRunnerMarker;

internal sealed class ConsoleOutput : Xunit.Abstractions.ITestOutputHelper
{
    public void WriteLine(string message) => Console.WriteLine("     | " + message);

    public void WriteLine(string format, params object[] args) => Console.WriteLine("     | " + string.Format(System.Globalization.CultureInfo.InvariantCulture, format, args));
}
