using System.Reflection;
using System.Reflection.Emit;

namespace XINSkan.SecurityTests.Infrastructure;

/// <summary>A call, construction or method-pointer load found in compiled IL.</summary>
internal sealed record IlCall(string CallerType, string Caller, string CalleeDocId, string CalleeTypeDocId);

/// <summary>
/// Reads the IL of every method in an assembly (including compiler-generated types: lambdas, async state
/// machines, iterators) and resolves call, callvirt, newobj, ldftn and ldvirtftn targets. Uses only reflection,
/// so it runs wherever the tests run and checks what was actually compiled, not just the source.
/// </summary>
internal static class IlScanner
{
    private static readonly OpCode[] OneByte = new OpCode[256];
    private static readonly OpCode[] TwoByte = new OpCode[256];

    static IlScanner()
    {
        foreach (var f in typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static))
        {
            var op = (OpCode)f.GetValue(null)!;
            var v = (ushort)op.Value;
            if (v < 0x100)
            {
                OneByte[v] = op;
            }
            else if ((v & 0xFF00) == 0xFE00)
            {
                TwoByte[v & 0xFF] = op;
            }
        }
    }

    public static (List<IlCall> Calls, List<string> Unresolved) Scan(Assembly assembly)
    {
        var calls = new List<IlCall>();
        var unresolved = new List<string>();
        Type[] types;
        try
        {
            types = assembly.GetTypes();
        }
        catch (ReflectionTypeLoadException ex)
        {
            types = ex.Types.Where(t => t is not null).ToArray()!;
            unresolved.Add($"{assembly.GetName().Name}: some types could not be loaded");
        }

        const BindingFlags all = BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;
        foreach (var type in types)
        {
            var methods = type.GetMethods(all).Cast<MethodBase>().Concat(type.GetConstructors(all));
            foreach (var m in methods)
            {
                byte[]? il;
                try
                {
                    il = m.GetMethodBody()?.GetILAsByteArray();
                }
                catch (Exception ex) when (ex is InvalidOperationException or NotSupportedException or BadImageFormatException)
                {
                    continue;
                }

                if (il is null)
                {
                    continue;
                }

                ScanBody(type, m, il, calls, unresolved);
            }
        }

        return (calls, unresolved);
    }

    private static void ScanBody(Type type, MethodBase method, byte[] il, List<IlCall> calls, List<string> unresolved)
    {
        var typeArgs = type.IsGenericType ? type.GetGenericArguments() : null;
        var methodArgs = method is MethodInfo { IsGenericMethod: true } mi ? mi.GetGenericArguments() : null;
        var i = 0;
        while (i < il.Length)
        {
            OpCode op;
            if (il[i] == 0xFE)
            {
                op = TwoByte[il[i + 1]];
                i += 2;
            }
            else
            {
                op = OneByte[il[i]];
                i += 1;
            }

            switch (op.OperandType)
            {
                case OperandType.InlineMethod:
                {
                    var token = BitConverter.ToInt32(il, i);
                    try
                    {
                        var target = method.Module.ResolveMethod(token, typeArgs, methodArgs);
                        if (target is not null)
                        {
                            var def = Canonical(target);
                            calls.Add(new IlCall(type.FullName ?? type.Name, method.Name, DocId.ForMethod(def), DocId.ForType(Definition(def.DeclaringType!))));
                        }
                    }
                    catch (Exception ex) when (ex is ArgumentException or MissingMethodException or TypeLoadException or BadImageFormatException or FileNotFoundException)
                    {
                        unresolved.Add($"{type.FullName}.{method.Name}: token 0x{token:X8} ({ex.GetType().Name})");
                    }

                    i += 4;
                    break;
                }

                case OperandType.InlineNone:
                    break;
                case OperandType.ShortInlineBrTarget:
                case OperandType.ShortInlineI:
                case OperandType.ShortInlineVar:
                    i += 1;
                    break;
                case OperandType.InlineVar:
                    i += 2;
                    break;
                case OperandType.InlineI8:
                case OperandType.InlineR:
                    i += 8;
                    break;
                case OperandType.InlineSwitch:
                    var n = BitConverter.ToInt32(il, i);
                    i += 4 + (4 * n);
                    break;
                default:
                    i += 4;
                    break;
            }
        }
    }

    private static Type Definition(Type t) => t.IsGenericType && !t.IsGenericTypeDefinition ? t.GetGenericTypeDefinition() : t;

    /// <summary>Maps a member of a constructed generic type or a generic method instance to its definition.</summary>
    private static MethodBase Canonical(MethodBase m)
    {
        if (m is MethodInfo { IsGenericMethod: true, IsGenericMethodDefinition: false } gm)
        {
            m = gm.GetGenericMethodDefinition();
        }

        if (m.DeclaringType is { IsGenericType: true, IsGenericTypeDefinition: false })
        {
            m = m.Module.ResolveMethod(m.MetadataToken)!;
        }

        return m;
    }
}
