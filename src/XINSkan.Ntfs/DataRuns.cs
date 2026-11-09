namespace XINSkan.Ntfs;

/// <summary>A contiguous piece of a non-resident attribute: <see cref="Length"/> clusters starting at <see cref="Lcn"/>.</summary>
/// <param name="Lcn">Logical cluster number on the volume; null for a sparse (unallocated) run.</param>
public readonly record struct DataRun(long? Lcn, long Length);

/// <summary>Decodes the mapping pairs ("data runs") of a non-resident attribute.</summary>
public static class DataRuns
{
    private const int MaxRuns = 1 << 20;

    /// <summary>Decodes until the terminating zero byte. Never throws; stops at the first inconsistency.</summary>
    /// <param name="problem">Why decoding stopped early, or null.</param>
    public static List<DataRun> Decode(ReadOnlySpan<byte> b, out string? problem)
    {
        problem = null;
        var runs = new List<DataRun>();
        long lcn = 0;
        var o = 0;
        while (o < b.Length)
        {
            var header = b[o];
            if (header == 0)
            {
                return runs;
            }

            var lengthBytes = header & 0x0F;
            var offsetBytes = header >> 4;
            if (lengthBytes is 0 or > 8 || offsetBytes > 8 || o + 1 + lengthBytes + offsetBytes > b.Length)
            {
                problem = $"Повреждённая цепочка кластеров (байт 0x{header:X2} на смещении {o}).";
                return runs;
            }

            var length = ReadUnsigned(b.Slice(o + 1, lengthBytes));
            if (length <= 0)
            {
                problem = $"Длина фрагмента {length} недопустима.";
                return runs;
            }

            long? start = null;
            if (offsetBytes > 0)
            {
                lcn += ReadSigned(b.Slice(o + 1 + lengthBytes, offsetBytes));
                if (lcn < 0)
                {
                    problem = "Фрагмент начинается до начала тома.";
                    return runs;
                }

                start = lcn;
            }

            runs.Add(new DataRun(start, length));
            if (runs.Count >= MaxRuns)
            {
                problem = "Слишком много фрагментов.";
                return runs;
            }

            o += 1 + lengthBytes + offsetBytes;
        }

        problem = "Цепочка кластеров не закончена нулевым байтом.";
        return runs;
    }

    private static long ReadUnsigned(ReadOnlySpan<byte> v)
    {
        ulong value = 0;
        for (var i = v.Length - 1; i >= 0; i--)
        {
            value = (value << 8) | v[i];
        }

        return value > long.MaxValue ? -1 : (long)value;
    }

    private static long ReadSigned(ReadOnlySpan<byte> v)
    {
        long value = 0;
        for (var i = v.Length - 1; i >= 0; i--)
        {
            value = (value << 8) | v[i];
        }

        // Sign-extend from the top byte.
        var bits = v.Length * 8;
        if (bits < 64 && (v[^1] & 0x80) != 0)
        {
            value |= -1L << bits;
        }

        return value;
    }
}
