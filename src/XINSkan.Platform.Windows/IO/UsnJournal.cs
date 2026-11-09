using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.Versioning;
using Microsoft.Win32.SafeHandles;

namespace XINSkan.Platform.Windows.IO;

/// <summary>Reads the NTFS change journal through FSCTL_QUERY_USN_JOURNAL and FSCTL_READ_USN_JOURNAL. Read only.</summary>
[SupportedOSPlatform("windows")]
public static class UsnJournal
{
    private const int ErrorJournalEntryDeleted = 1181;
    private const int ReadBufferSize = 1 << 20;

    /// <summary>Raw USN_JOURNAL_DATA (parse with XINSkan.Ntfs.UsnJournalInfo).</summary>
    public static byte[] Query(SafeFileHandle volume)
    {
        var data = new byte[80];
        var n = SafeIoControl.Invoke(volume, AllowedIoControl.QueryUsnJournal, default, data);
        return data[..n];
    }

    /// <summary>
    /// Blocks of records from <paramref name="startUsn"/> up to <paramref name="untilUsn"/> (the next USN at the
    /// time of the query, so a busy system cannot keep the read going forever). Each block holds whole records.
    /// </summary>
    /// <param name="restartedAt">Called when the journal overwrote records while being read; reading resumes at the given USN.</param>
    public static IEnumerable<byte[]> Read(
        SafeFileHandle volume,
        ulong journalId,
        long startUsn,
        long untilUsn,
        Func<long>? onEntriesDeleted,
        CancellationToken cancellationToken)
    {
        var input = new byte[48];
        var output = new byte[ReadBufferSize];
        var start = startUsn;
        while (start < untilUsn)
        {
            cancellationToken.ThrowIfCancellationRequested();
            BinaryPrimitives.WriteInt64LittleEndian(input, start);
            BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(8), 0xFFFF_FFFF); // every reason
            BinaryPrimitives.WriteUInt32LittleEndian(input.AsSpan(12), 0);          // not only on close
            BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(16), 0);          // no timeout
            BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(24), 0);          // do not wait for data
            BinaryPrimitives.WriteUInt64LittleEndian(input.AsSpan(32), journalId);
            BinaryPrimitives.WriteUInt16LittleEndian(input.AsSpan(40), 2);          // MinMajorVersion
            BinaryPrimitives.WriteUInt16LittleEndian(input.AsSpan(42), 3);          // MaxMajorVersion

            int n;
            try
            {
                n = SafeIoControl.Invoke(volume, AllowedIoControl.ReadUsnJournal, input, output);
            }
            catch (Win32Exception ex) when (ex.NativeErrorCode == ErrorJournalEntryDeleted && onEntriesDeleted is not null)
            {
                start = onEntriesDeleted();
                continue;
            }

            var next = n >= 8 ? BinaryPrimitives.ReadInt64LittleEndian(output) : start;
            if (n <= 8 || next <= start)
            {
                yield break;
            }

            yield return output[8..n];
            start = next;
        }
    }
}
