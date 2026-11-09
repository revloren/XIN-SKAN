namespace XINSkan.Analyzers.Minecraft;

/// <summary>A JVM option that changes what code the game runs, and the file it points to.</summary>
public sealed record JvmFlag(string Kind, string Option, string? Path, string Meaning);

/// <summary>
/// Finds JVM options that load extra code into the game or weaken its checks. Each is a legitimate tool (profilers,
/// debuggers, performance agents) and also the usual way to inject a client, so each is an indirect sign.
/// </summary>
public static class JvmArguments
{
    /// <summary>Splits a command line the way the launchers do: spaces, with double quotes grouping.</summary>
    public static IReadOnlyList<string> Split(string? line)
    {
        var result = new List<string>();
        if (string.IsNullOrWhiteSpace(line))
        {
            return result;
        }

        var current = new System.Text.StringBuilder();
        var quoted = false;
        foreach (var c in line)
        {
            if (c == '"')
            {
                quoted = !quoted;
            }
            else if (char.IsWhiteSpace(c) && !quoted)
            {
                if (current.Length > 0)
                {
                    result.Add(current.ToString());
                    current.Clear();
                }
            }
            else
            {
                current.Append(c);
            }
        }

        if (current.Length > 0)
        {
            result.Add(current.ToString());
        }

        return result;
    }

    public static IReadOnlyList<JvmFlag> Find(IEnumerable<string> arguments)
    {
        ArgumentNullException.ThrowIfNull(arguments);
        var flags = new List<JvmFlag>();
        foreach (var a in arguments)
        {
            if (a.StartsWith("-javaagent:", StringComparison.OrdinalIgnoreCase))
            {
                var value = a[11..];
                var eq = value.IndexOf('=', StringComparison.Ordinal);
                flags.Add(new JvmFlag("javaagent", a, eq < 0 ? value : value[..eq], "подключает Java-агент: его код выполняется до игры и может менять её классы"));
            }
            else if (a.StartsWith("-agentpath:", StringComparison.OrdinalIgnoreCase))
            {
                var value = a[11..];
                var eq = value.IndexOf('=', StringComparison.Ordinal);
                flags.Add(new JvmFlag("agentpath", a, eq < 0 ? value : value[..eq], "подключает нативный агент (DLL) к процессу игры"));
            }
            else if (a.StartsWith("-agentlib:", StringComparison.OrdinalIgnoreCase))
            {
                flags.Add(new JvmFlag("agentlib", a, null, a.StartsWith("-agentlib:jdwp", StringComparison.OrdinalIgnoreCase)
                    ? "включает отладчик: к игре можно подключиться и менять её на ходу"
                    : "подключает нативный агент по имени библиотеки"));
            }
            else if (a.StartsWith("-Xbootclasspath/", StringComparison.OrdinalIgnoreCase))
            {
                var colon = a.IndexOf(':', StringComparison.Ordinal);
                flags.Add(new JvmFlag("bootclasspath", a, colon < 0 ? null : a[(colon + 1)..].Split(';')[0], "добавляет классы раньше классов самой Java"));
            }
            else if (a.Equals("-noverify", StringComparison.OrdinalIgnoreCase) || a.Equals("-Xverify:none", StringComparison.OrdinalIgnoreCase))
            {
                flags.Add(new JvmFlag("noverify", a, null, "отключает проверку байт-кода: так запускают изменённые классы, которые иначе не загрузились бы"));
            }
            else if (a.StartsWith("-Djava.system.class.loader=", StringComparison.OrdinalIgnoreCase))
            {
                flags.Add(new JvmFlag("classloader", a, null, "заменяет системный загрузчик классов"));
            }
            else if (a.StartsWith("-Dfabric.addMods=", StringComparison.OrdinalIgnoreCase) || a.StartsWith("-Dfml.coreMods.load=", StringComparison.OrdinalIgnoreCase)
                     || a.StartsWith("-Dfml.coreMods.", StringComparison.OrdinalIgnoreCase))
            {
                var eq = a.IndexOf('=', StringComparison.Ordinal);
                flags.Add(new JvmFlag("extramods", a, eq < 0 ? null : a[(eq + 1)..].Split(';')[0], "загружает моды или core-моды не из папки mods"));
            }
        }

        return flags;
    }
}
