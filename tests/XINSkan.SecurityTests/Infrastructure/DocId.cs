using System.Reflection;

namespace XINSkan.SecurityTests.Infrastructure;

/// <summary>
/// Documentation-comment IDs ("M:System.IO.File.Delete(System.String)") for reflection members, in the format
/// BannedSymbols.txt and BannedApiAnalyzers use. Covers the shapes that occur in the ban list and in IL calls.
/// </summary>
internal static class DocId
{
    public static string ForType(Type t) => "T:" + TypeName(t);

    public static string ForMethod(MethodBase m)
    {
        var name = m switch
        {
            ConstructorInfo { IsStatic: true } => "#cctor",
            ConstructorInfo => "#ctor",
            _ => m.Name,
        };

        if (m is MethodInfo { IsGenericMethodDefinition: true } gm)
        {
            name += "``" + gm.GetGenericArguments().Length;
        }

        var ps = m.GetParameters();
        var args = ps.Length == 0 ? string.Empty : "(" + string.Join(",", ps.Select(p => TypeName(p.ParameterType))) + ")";
        return "M:" + TypeName(m.DeclaringType!) + "." + name + args;
    }

    public static string TypeName(Type t)
    {
        if (t.IsGenericParameter)
        {
            return (t.DeclaringMethod is not null ? "``" : "`") + t.GenericParameterPosition;
        }

        if (t.IsByRef)
        {
            return TypeName(t.GetElementType()!) + "@";
        }

        if (t.IsPointer)
        {
            return TypeName(t.GetElementType()!) + "*";
        }

        if (t.IsArray)
        {
            var rank = t.GetArrayRank();
            return TypeName(t.GetElementType()!) + (t.IsSZArray ? "[]" : "[" + string.Join(",", Enumerable.Repeat("0:", rank)) + "]");
        }

        if (t.IsGenericType && !t.IsGenericTypeDefinition)
        {
            var def = TypeName(t.GetGenericTypeDefinition());
            var tick = def.LastIndexOf('`');
            var bare = tick > 0 ? def[..tick] : def;
            return bare + "{" + string.Join(",", t.GetGenericArguments().Select(TypeName)) + "}";
        }

        var full = t.FullName ?? (t.Namespace + "." + t.Name);
        return full.Replace('+', '.');
    }

    /// <summary>Every doc ID of the public surface of the given assemblies (types, methods, constructors, accessors).</summary>
    public static HashSet<string> PublicSurface(IEnumerable<Assembly> assemblies)
    {
        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (var asm in assemblies)
        {
            foreach (var type in asm.GetExportedTypes())
            {
                ids.Add(ForType(type));
                const BindingFlags all = BindingFlags.Public | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
                foreach (var m in type.GetMethods(all))
                {
                    ids.Add(ForMethod(m));
                }

                foreach (var c in type.GetConstructors(all))
                {
                    ids.Add(ForMethod(c));
                }
            }
        }

        return ids;
    }
}
