using System.Buffers.Binary;
using System.Text;

namespace XINSkan.ExecutionTests;

/// <summary>A file a synthetic Prefetch run touched.</summary>
internal sealed record PfFile(string Path, ulong Entry = 0, ushort Sequence = 0);

/// <summary>Builds Prefetch files (versions 17, 23, 26, 30) by the published layout, and compresses them.</summary>
internal static class PrefetchBuilder
{
    private sealed record Layout(int InfoSize, int RunTimesOffset, int RunTimes, int RunCountOffset, int MetricSize, int VolumeEntrySize);

    private static Layout For(int version) => version switch
    {
        17 => new Layout(68, 36, 1, 60, 20, 40),
        23 => new Layout(156, 44, 1, 68, 32, 104),
        26 => new Layout(224, 44, 8, 124, 32, 104),
        30 => new Layout(224, 44, 8, 124, 32, 96),
        _ => throw new ArgumentOutOfRangeException(nameof(version)),
    };

    /// <param name="movedRunCount">Newer Windows 11 builds: run count 8 bytes earlier, nonzero value before the old place.</param>
    public static byte[] Build(int version, string executable, uint hash, int runCount, long[] runTimes, PfFile[] files,
        string device = @"\VOLUME{01d1b0e3a1b2c3d4-64BB3469}", uint serial = 0x64BB3469, string[]? directories = null, bool movedRunCount = false)
    {
        var l = For(version);
        var infoStart = 84;
        var metricsOffset = infoStart + l.InfoSize;
        var stringsOffset = metricsOffset + (files.Length * l.MetricSize);
        var strings = new MemoryStream();
        var nameOffsets = new List<int>();
        foreach (var f in files)
        {
            nameOffsets.Add((int)strings.Length);
            var b = Encoding.Unicode.GetBytes(f.Path + "\0");
            strings.Write(b);
        }

        var stringsBytes = strings.ToArray();
        var volumesOffset = Align(stringsOffset + stringsBytes.Length);

        // Volume block: entry, device path, file references, directory strings.
        var dirs = directories ?? [];
        var entry = new byte[l.VolumeEntrySize];
        var devBytes = Encoding.Unicode.GetBytes(device + "\0");
        var devOffset = l.VolumeEntrySize;
        var refs = new MemoryStream();
        var refsHeader = new byte[16];
        BinaryPrimitives.WriteInt32LittleEndian(refsHeader, 3);
        BinaryPrimitives.WriteInt32LittleEndian(refsHeader.AsSpan(4), files.Length);
        refs.Write(refsHeader);
        foreach (var f in files)
        {
            var r = new byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(r, (f.Entry & 0xFFFF_FFFF_FFFF) | ((ulong)f.Sequence << 48));
            refs.Write(r);
        }

        var refsOffset = Align(devOffset + devBytes.Length);
        var dirsStream = new MemoryStream();
        foreach (var d in dirs)
        {
            var len = new byte[2];
            BinaryPrimitives.WriteUInt16LittleEndian(len, (ushort)d.Length);
            dirsStream.Write(len);
            dirsStream.Write(Encoding.Unicode.GetBytes(d + "\0"));
        }

        var dirsOffset = Align(refsOffset + (int)refs.Length);
        var volumeBlock = new byte[dirsOffset + dirsStream.Length];
        BinaryPrimitives.WriteInt32LittleEndian(entry, devOffset);
        BinaryPrimitives.WriteInt32LittleEndian(entry.AsSpan(4), device.Length);
        BinaryPrimitives.WriteInt64LittleEndian(entry.AsSpan(8), 130_000_000_000_000_000);
        BinaryPrimitives.WriteUInt32LittleEndian(entry.AsSpan(16), serial);
        BinaryPrimitives.WriteInt32LittleEndian(entry.AsSpan(20), refsOffset);
        BinaryPrimitives.WriteInt32LittleEndian(entry.AsSpan(24), (int)refs.Length);
        BinaryPrimitives.WriteInt32LittleEndian(entry.AsSpan(28), dirsOffset);
        BinaryPrimitives.WriteInt32LittleEndian(entry.AsSpan(32), dirs.Length);
        entry.CopyTo(volumeBlock, 0);
        devBytes.CopyTo(volumeBlock, devOffset);
        refs.ToArray().CopyTo(volumeBlock, refsOffset);
        dirsStream.ToArray().CopyTo(volumeBlock, dirsOffset);

        var total = volumesOffset + volumeBlock.Length;
        var pf = new byte[total];
        BinaryPrimitives.WriteInt32LittleEndian(pf, version);
        "SCCA"u8.CopyTo(pf.AsSpan(4));
        BinaryPrimitives.WriteInt32LittleEndian(pf.AsSpan(8), 0x11);
        BinaryPrimitives.WriteInt32LittleEndian(pf.AsSpan(12), total);
        Encoding.Unicode.GetBytes(executable).CopyTo(pf.AsSpan(16, 58));
        BinaryPrimitives.WriteUInt32LittleEndian(pf.AsSpan(76), hash);

        var info = pf.AsSpan(infoStart, l.InfoSize);
        BinaryPrimitives.WriteInt32LittleEndian(info, metricsOffset);
        BinaryPrimitives.WriteInt32LittleEndian(info[4..], files.Length);
        BinaryPrimitives.WriteInt32LittleEndian(info[16..], stringsOffset);
        BinaryPrimitives.WriteInt32LittleEndian(info[20..], stringsBytes.Length);
        BinaryPrimitives.WriteInt32LittleEndian(info[24..], volumesOffset);
        BinaryPrimitives.WriteInt32LittleEndian(info[28..], 1);
        BinaryPrimitives.WriteInt32LittleEndian(info[32..], volumeBlock.Length);
        for (var i = 0; i < Math.Min(l.RunTimes, runTimes.Length); i++)
        {
            BinaryPrimitives.WriteInt64LittleEndian(info[(l.RunTimesOffset + (i * 8))..], runTimes[i]);
        }

        if (movedRunCount)
        {
            BinaryPrimitives.WriteInt32LittleEndian(info[(l.RunCountOffset - 8)..], runCount);
            BinaryPrimitives.WriteInt32LittleEndian(info[(l.RunCountOffset - 4)..], 1);
            BinaryPrimitives.WriteInt32LittleEndian(info[l.RunCountOffset..], 0x7777);
        }
        else
        {
            BinaryPrimitives.WriteInt32LittleEndian(info[l.RunCountOffset..], runCount);
        }

        for (var i = 0; i < files.Length; i++)
        {
            var m = pf.AsSpan(metricsOffset + (i * l.MetricSize), l.MetricSize);
            if (l.MetricSize == 20)
            {
                BinaryPrimitives.WriteInt32LittleEndian(m[8..], nameOffsets[i]);
                BinaryPrimitives.WriteInt32LittleEndian(m[12..], files[i].Path.Length);
            }
            else
            {
                BinaryPrimitives.WriteInt32LittleEndian(m[12..], nameOffsets[i]);
                BinaryPrimitives.WriteInt32LittleEndian(m[16..], files[i].Path.Length);
                BinaryPrimitives.WriteUInt32LittleEndian(m[24..], (uint)files[i].Entry);
                BinaryPrimitives.WriteUInt16LittleEndian(m[28..], (ushort)(files[i].Entry >> 32));
                BinaryPrimitives.WriteUInt16LittleEndian(m[30..], files[i].Sequence);
            }
        }

        stringsBytes.CopyTo(pf, stringsOffset);
        volumeBlock.CopyTo(pf, volumesOffset);
        return pf;
    }

    /// <summary>Wraps data as a Windows 10 MAM file (XPRESS Huffman, no checksum).</summary>
    public static byte[] Mam(byte[] data)
    {
        var compressed = XpressEncoder.Encode(data);
        var result = new byte[8 + compressed.Length];
        "MAM"u8.CopyTo(result);
        result[3] = 0x04;
        BinaryPrimitives.WriteInt32LittleEndian(result.AsSpan(4), data.Length);
        compressed.CopyTo(result, 8);
        return result;
    }

    private static int Align(int n) => (n + 7) & ~7;
}

/// <summary>
/// A deliberately simple XPRESS Huffman encoder for tests (MS-XCA 2.2.4): every one of the 512 symbols has a
/// 9-bit code, so the code of a symbol is the symbol itself; matches of 3–17 bytes up to 64 KB back. One block
/// per 64 KB of output; block boundaries follow the decoder's rule (next table after the words already read).
/// </summary>
internal static class XpressEncoder
{
    public static byte[] Encode(byte[] data)
    {
        var output = new MemoryStream();
        for (var start = 0; start < data.Length || start == 0; start += 65536)
        {
            var end = Math.Min(start + 65536, data.Length);
            output.Write(Enumerable.Repeat((byte)0x99, 256).ToArray());
            var bits = new BitWriter();
            var i = start;
            while (i < end)
            {
                var (len, off) = FindMatch(data, i, end);
                if (len >= 3)
                {
                    var offsetBits = 31 - int.LeadingZeroCount(off);
                    bits.Write((uint)(256 + ((offsetBits << 4) | (len - 3))), 9);
                    bits.Write((uint)(off - (1 << offsetBits)), offsetBits);
                    i += len;
                }
                else
                {
                    bits.Write(data[i], 9);
                    i++;
                }
            }

            output.Write(bits.Finish());
            if (data.Length == 0)
            {
                break;
            }
        }

        return output.ToArray();
    }

    private static (int Length, int Offset) FindMatch(byte[] data, int i, int end)
    {
        var best = (0, 0);
        for (var off = 1; off <= Math.Min(i, 4096); off++)
        {
            var n = 0;
            while (n < 17 && i + n < end && data[i + n] == data[i + n - off])
            {
                n++;
            }

            if (n > best.Item1)
            {
                best = (n, off);
            }
        }

        return best;
    }

    /// <summary>
    /// Bits MSB-first in 16-bit little-endian words. The decoder reads two words ahead and takes the next table
    /// from the position after the last word it read: the block is padded so that position is right after it.
    /// </summary>
    private sealed class BitWriter
    {
        private readonly List<ushort> _words = [];
        private uint _acc;
        private int _count;
        private int _total;

        public void Write(uint value, int n)
        {
            for (var b = n - 1; b >= 0; b--)
            {
                _acc = (_acc << 1) | ((value >> b) & 1);
                _count++;
                _total++;
                if (_count == 16)
                {
                    _words.Add((ushort)_acc);
                    _acc = 0;
                    _count = 0;
                }
            }
        }

        public byte[] Finish()
        {
            // The decoder starts with two words and reads one more each time its consumed count passes 16·k
            // (k ≥ 1), so after c bits it has read 2 + (c − 1) / 16 words.
            var refills = _total == 0 ? 0 : (_total - 1) / 16;
            var wordsRead = 2 + refills;
            if (_count > 0)
            {
                _words.Add((ushort)(_acc << (16 - _count)));
            }

            while (_words.Count < wordsRead)
            {
                _words.Add(0);
            }

            var result = new byte[wordsRead * 2];
            for (var w = 0; w < wordsRead; w++)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(w * 2), _words[w]);
            }

            return result;
        }
    }
}
