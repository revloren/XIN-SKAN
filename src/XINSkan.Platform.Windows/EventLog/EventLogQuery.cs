using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;
using XINSkan.Platform.Windows.Native;

namespace XINSkan.Platform.Windows.EventLog;

/// <summary>A query handle or event handle of the Windows Event Log API, closed with EvtClose.</summary>
[SupportedOSPlatform("windows")]
internal sealed class EvtHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public EvtHandle()
        : base(ownsHandle: true)
    {
    }

    internal EvtHandle(nint handle)
        : base(ownsHandle: true) => SetHandle(handle);

    protected override bool ReleaseHandle() => NativeMethods.EvtClose(handle);
}

/// <summary>
/// Reads events from the live event logs as XML (EvtQuery, EvtNext, EvtRender). Query and render only: the
/// functions that clear, export or configure logs are not imported (SecurityTests check the import list).
/// </summary>
[SupportedOSPlatform("windows")]
public static class EventLogQuery
{
    private const uint QueryChannelPath = 0x1;
    private const uint QueryReverseDirection = 0x200;
    private const uint QueryTolerateQueryErrors = 0x1000;
    private const uint RenderEventXml = 1;
    private const int ErrorNoMoreItems = 259;
    private const int ErrorInsufficientBuffer = 122;

    /// <summary>Events of a channel matching an XPath filter, as XML, oldest first (or newest first).</summary>
    /// <exception cref="Win32Exception">The channel does not exist (15007) or cannot be read (5).</exception>
    public static IEnumerable<string> Query(string channel, string xpath, bool newestFirst = false, int max = int.MaxValue)
    {
        ArgumentNullException.ThrowIfNull(channel);
        ArgumentNullException.ThrowIfNull(xpath);
        var flags = QueryChannelPath | QueryTolerateQueryErrors | (newestFirst ? QueryReverseDirection : 0);
        var query = NativeMethods.EvtQuery(0, channel, xpath, flags);
        if (query.IsInvalid)
        {
            var error = Marshal.GetLastPInvokeError();
            query.Dispose();
            throw new Win32Exception(error);
        }

        return Read(query, max);
    }

    private static IEnumerable<string> Read(EvtHandle query, int max)
    {
        using (query)
        {
            var batch = new nint[64];
            for (var total = 0; total < max;)
            {
                if (!Next(query, batch, out var count))
                {
                    yield break;
                }

                for (var i = 0; i < count; i++)
                {
                    using var e = new EvtHandle(batch[i]);
                    if (total < max && Render(e) is { } xml)
                    {
                        total++;
                        yield return xml;
                    }
                }
            }
        }
    }

    private static unsafe bool Next(EvtHandle query, nint[] batch, out int count)
    {
        fixed (nint* events = batch)
        {
            if (NativeMethods.EvtNext(query, (uint)batch.Length, events, 5000, 0, out var n))
            {
                count = (int)n;
                return true;
            }
        }

        var error = Marshal.GetLastPInvokeError();
        count = 0;
        return error == ErrorNoMoreItems ? false : throw new Win32Exception(error);
    }

    private static unsafe string? Render(EvtHandle e)
    {
        if (!NativeMethods.EvtRender(0, e, RenderEventXml, 0, null, out var used, out _))
        {
            if (Marshal.GetLastPInvokeError() != ErrorInsufficientBuffer || used == 0 || used > 16 * 1024 * 1024)
            {
                return null;
            }
        }

        var buffer = new char[(used / 2) + 1];
        fixed (char* p = buffer)
        {
            if (!NativeMethods.EvtRender(0, e, RenderEventXml, used, p, out used, out _))
            {
                return null;
            }
        }

        return new string(buffer, 0, (int)(used / 2)).TrimEnd('\0');
    }
}
