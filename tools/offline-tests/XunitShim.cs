// Minimal stand-in for the parts of xUnit the test suite uses, so tests can run in a sandbox without NuGet.
// CI always runs the real xUnit; this shim exists only for quick local feedback (see README.md).
using System.Collections;
using System.Reflection;

namespace Xunit
{

[AttributeUsage(AttributeTargets.Method)]
public class FactAttribute : Attribute
{
    public string? Skip { get; set; }
}

[AttributeUsage(AttributeTargets.Method)]
public sealed class TheoryAttribute : FactAttribute;

[AttributeUsage(AttributeTargets.Method, AllowMultiple = true)]
public sealed class InlineDataAttribute(params object?[] data) : Attribute
{
    public object?[] Data { get; } = data ?? [null];
}

public sealed class AssertException(string message) : Exception(message);

public static class Assert
{
    public static void True(bool condition, string? message = null) { if (!condition) Fail(message ?? "Expected true."); }

    public static void False(bool condition, string? message = null) { if (condition) Fail(message ?? "Expected false."); }

    public static void Null(object? value) { if (value is not null) Fail($"Expected null, got {value}."); }

    public static void NotNull(object? value) { if (value is null) Fail("Expected not null."); }

    public static void Equal(string? expected, string? actual) { if (!string.Equals(expected, actual, StringComparison.Ordinal)) Fail($"Expected '{expected}', got '{actual}'."); }

    public static void Equal<T>(T expected, T actual)
    {
        if (expected is IEnumerable e && actual is IEnumerable a && expected is not string)
        {
            SequenceEqual(e.Cast<object?>().ToList(), a.Cast<object?>().ToList());
            return;
        }

        if (!EqualityComparer<T>.Default.Equals(expected, actual)) Fail($"Expected {expected}, got {actual}.");
    }

    public static void Equal<T>(IEnumerable<T> expected, IEnumerable<T> actual) => SequenceEqual(expected.Cast<object?>().ToList(), actual.Cast<object?>().ToList());

    private static void SequenceEqual(List<object?> e, List<object?> a)
    {
        if (e.Count != a.Count || !e.Zip(a).All(p => Equals(p.First, p.Second)))
            Fail($"Expected [{string.Join(", ", e)}], got [{string.Join(", ", a)}].");
    }

    public static void NotEqual<T>(T expected, T actual) { if (EqualityComparer<T>.Default.Equals(expected, actual)) Fail($"Did not expect {actual}."); }

    public static void Contains(string expected, string? actual, StringComparison comparison = StringComparison.Ordinal)
    { if (actual is null || !actual.Contains(expected, comparison)) Fail($"'{actual}' does not contain '{expected}'."); }

    public static void StartsWith(string expected, string? actual, StringComparison comparison = StringComparison.Ordinal) { if (actual is null || !actual.StartsWith(expected, comparison)) Fail($"'{actual}' does not start with '{expected}'."); }

    public static void EndsWith(string expected, string? actual, StringComparison comparison = StringComparison.Ordinal) { if (actual is null || !actual.EndsWith(expected, comparison)) Fail($"'{actual}' does not end with '{expected}'."); }

    public static T Single<T>(IEnumerable<T> collection, Predicate<T> filter) { var m = collection.Where(x => filter(x)).ToList(); if (m.Count != 1) Fail($"Expected one matching item, found {m.Count}."); return m[0]; }

    public static void InRange<T>(T actual, T low, T high) where T : IComparable<T> { if (actual.CompareTo(low) < 0 || actual.CompareTo(high) > 0) Fail($"{actual} is not in [{low}, {high}]."); }

    public static void Matches(string pattern, string? actual) { if (actual is null || !System.Text.RegularExpressions.Regex.IsMatch(actual, pattern)) Fail($"'{actual}' does not match '{pattern}'."); }

    public static void Same(object? expected, object? actual) { if (!ReferenceEquals(expected, actual)) Fail("Objects are not the same instance."); }

    public static void Contains<T>(T expected, IEnumerable<T> collection) { if (!collection.Contains(expected)) Fail($"Collection does not contain {expected}."); }

    public static void Contains<T>(IEnumerable<T> collection, Predicate<T> filter) { if (!collection.Any(x => filter(x))) Fail("No item matches the filter. Items: " + string.Join(" | ", collection)); }

    public static void DoesNotContain<T>(IEnumerable<T> collection, Predicate<T> filter) { if (collection.Any(x => filter(x))) Fail("An item matches the filter."); }

    public static void DoesNotContain(string expected, string? actual, StringComparison comparison = StringComparison.Ordinal)
    { if (actual is not null && actual.Contains(expected, comparison)) Fail($"'{actual}' contains '{expected}'."); }

    public static void Empty(IEnumerable collection) { var items = collection.Cast<object?>().ToList(); if (items.Count != 0) Fail("Expected empty, got: " + string.Join(" | ", items)); }

    public static void NotEmpty(IEnumerable collection) { if (!collection.Cast<object?>().Any()) Fail("Expected not empty."); }

    public static T Single<T>(IEnumerable<T> collection) { var l = collection.ToList(); if (l.Count != 1) Fail($"Expected one item, got {l.Count}."); return l[0]; }

    public static void Single(IEnumerable collection) { var c = collection.Cast<object?>().Count(); if (c != 1) Fail($"Expected one item, got {c}."); }

    public static void Subset<T>(ISet<T> expectedSuperset, ISet<T>? actual) { if (actual is null || !actual.IsSubsetOf(expectedSuperset)) Fail("Not a subset: " + string.Join(", ", actual ?? new HashSet<T>())); }

    public static void All<T>(IEnumerable<T> collection, Action<T> action) { foreach (var x in collection) action(x); }

    public static T IsType<T>(object? value) { if (value is not T t || value.GetType() != typeof(T)) { Fail($"Expected {typeof(T)}, got {value?.GetType()}."); return default!; } return t; }

    public static T Throws<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (Exception ex) { return Check<T>(ex); }
        Fail($"Expected {typeof(T).Name}, nothing was thrown."); return null!;
    }

    public static T Throws<T>(Func<object?> func) where T : Exception => Throws<T>(() => { _ = func(); });

    public static async Task<T> ThrowsAsync<T>(Func<Task> func) where T : Exception
    {
        try { await func(); }
        catch (Exception ex) { return Check<T>(ex); }
        Fail($"Expected {typeof(T).Name}, nothing was thrown."); return null!;
    }

    public static async Task<T> ThrowsAnyAsync<T>(Func<Task> func) where T : Exception
    {
        try { await func(); }
        catch (T ex) { return ex; }
        Fail($"Expected {typeof(T).Name} or derived, nothing matching was thrown."); return null!;
    }

    public static T ThrowsAny<T>(Action action) where T : Exception
    {
        try { action(); }
        catch (T ex) { return ex; }
        Fail($"Expected {typeof(T).Name} or derived."); return null!;
    }

    private static T Check<T>(Exception ex) where T : Exception
    {
        if (ex.GetType() != typeof(T)) Fail($"Expected exactly {typeof(T).Name}, got {ex.GetType().Name}: {ex.Message}");
        return (T)ex;
    }

    public static void Fail(string message) => throw new AssertException(message);
}
}

namespace Xunit.Abstractions
{
    public interface ITestOutputHelper
    {
        void WriteLine(string message);

        void WriteLine(string format, params object[] args);
    }
}
