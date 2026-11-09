namespace XINSkan.ShellFormatsTests;

/// <summary>Skipped without XINSKAN_SHELL_SAMPLES unless XINSKAN_REQUIRE_SAMPLES=1.</summary>
public sealed class ShellSampleFactAttribute : FactAttribute
{
    public ShellSampleFactAttribute()
    {
        if (Root is null && Environment.GetEnvironmentVariable("XINSKAN_REQUIRE_SAMPLES") != "1")
        {
            Skip = "XINSKAN_SHELL_SAMPLES is not set.";
        }
    }

    public static string? Root => Environment.GetEnvironmentVariable("XINSKAN_SHELL_SAMPLES") is { Length: > 0 } p ? p : null;

    public static string File(params string[] parts) => Path.Combine([Root ?? throw new InvalidOperationException("XINSKAN_SHELL_SAMPLES is required but not set."), .. parts]);
}

public sealed class ShellSampleTheoryAttribute : TheoryAttribute
{
    public ShellSampleTheoryAttribute()
    {
        if (ShellSampleFactAttribute.Root is null && Environment.GetEnvironmentVariable("XINSKAN_REQUIRE_SAMPLES") != "1")
        {
            Skip = "XINSKAN_SHELL_SAMPLES is not set.";
        }
    }
}
