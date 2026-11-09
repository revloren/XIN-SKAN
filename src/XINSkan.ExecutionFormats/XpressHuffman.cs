using System.Buffers.Binary;

namespace XINSkan.ExecutionFormats;

/// <summary>
/// LZ77 + Huffman decompression as specified in MS-XCA 2.2.4 ("XPRESS Huffman"), used by Windows 10/11 Prefetch
/// (MAM files). Every read and copy is bounds-checked; damaged input ends with <see cref="InvalidDataException"/>.
/// </summary>
public static class XpressHuffman
{
    private const int BlockSize = 65536;
    private const int TableBits = 15;

    public static byte[] Decompress(ReadOnlySpan<byte> input, int outputSize)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(outputSize);
        var output = new byte[outputSize];
        var table = new ushort[1 << TableBits];
        var lengths = new byte[512];
        var inPos = 0;
        var outPos = 0;
        while (outPos < outputSize)
        {
            if (inPos + 256 + 4 > input.Length)
            {
                throw new InvalidDataException($"Сжатые данные обрываются на {inPos} (выведено {outPos} из {outputSize}).");
            }

            for (var i = 0; i < 256; i++)
            {
                lengths[i * 2] = (byte)(input[inPos + i] & 0x0F);
                lengths[(i * 2) + 1] = (byte)(input[inPos + i] >> 4);
            }

            BuildTable(lengths, table);
            var pos = inPos + 256;
            uint nextBits = (uint)BinaryPrimitives.ReadUInt16LittleEndian(input[pos..]) << 16;
            nextBits |= BinaryPrimitives.ReadUInt16LittleEndian(input[(pos + 2)..]);
            pos += 4;
            var extra = 16;
            var blockEnd = Math.Min(outPos + BlockSize, outputSize);
            while (outPos < blockEnd)
            {
                var entry = table[nextBits >> (32 - TableBits)];
                int length = entry & 0x0F;
                int symbol = entry >> 4;
                if (length == 0)
                {
                    throw new InvalidDataException("Неверный код Хаффмана.");
                }

                Consume(input, ref nextBits, ref extra, ref pos, length);
                if (symbol < 256)
                {
                    output[outPos++] = (byte)symbol;
                    continue;
                }

                symbol -= 256;
                var matchLength = symbol & 0x0F;
                var offsetBits = symbol >> 4;
                if (matchLength == 15)
                {
                    if (pos >= input.Length)
                    {
                        throw new InvalidDataException("Длина совпадения обрывается.");
                    }

                    matchLength = input[pos++];
                    if (matchLength == 255)
                    {
                        if (pos + 2 > input.Length)
                        {
                            throw new InvalidDataException("Длина совпадения обрывается.");
                        }

                        matchLength = BinaryPrimitives.ReadUInt16LittleEndian(input[pos..]);
                        pos += 2;
                        if (matchLength == 0)
                        {
                            if (pos + 4 > input.Length)
                            {
                                throw new InvalidDataException("Длина совпадения обрывается.");
                            }

                            var big = BinaryPrimitives.ReadUInt32LittleEndian(input[pos..]);
                            pos += 4;
                            if (big > int.MaxValue)
                            {
                                throw new InvalidDataException("Длина совпадения слишком велика.");
                            }

                            matchLength = (int)big;
                        }

                        if (matchLength < 15)
                        {
                            throw new InvalidDataException("Неверная длина совпадения.");
                        }

                        matchLength -= 15;
                    }

                    matchLength += 15;
                }

                matchLength += 3;
                var offset = (int)((nextBits >> 1) >> (31 - offsetBits)) | (1 << offsetBits);
                Consume(input, ref nextBits, ref extra, ref pos, offsetBits);
                if (offset > outPos)
                {
                    throw new InvalidDataException($"Ссылка назад на {offset} байт до начала данных.");
                }

                if (matchLength > outputSize - outPos)
                {
                    matchLength = outputSize - outPos; // the last match may be cut by the declared size
                }

                for (var i = 0; i < matchLength; i++)
                {
                    output[outPos] = output[outPos - offset];
                    outPos++;
                }
            }

            inPos = pos;
        }

        return output;
    }

    private static void Consume(ReadOnlySpan<byte> input, ref uint nextBits, ref int extra, ref int pos, int count)
    {
        if (count == 0)
        {
            return;
        }

        nextBits <<= count;
        extra -= count;
        if (extra < 0)
        {
            // Past the end the stream is padded with zeros; reading further fails only if the result is used.
            uint word = pos + 2 <= input.Length ? BinaryPrimitives.ReadUInt16LittleEndian(input[pos..]) : 0u;
            pos += 2;
            nextBits |= word << -extra;
            extra += 16;
        }
    }

    /// <summary>Canonical Huffman codes in (length, symbol) order; each table slot holds symbol &lt;&lt; 4 | length.</summary>
    private static void BuildTable(byte[] lengths, ushort[] table)
    {
        Array.Clear(table);
        var code = 0;
        for (var bits = 1; bits <= TableBits; bits++)
        {
            for (var symbol = 0; symbol < 512; symbol++)
            {
                if (lengths[symbol] != bits)
                {
                    continue;
                }

                var span = 1 << (TableBits - bits);
                var start = code << (TableBits - bits);
                if (start + span > table.Length)
                {
                    throw new InvalidDataException("Таблица Хаффмана переполнена.");
                }

                table.AsSpan(start, span).Fill((ushort)((symbol << 4) | bits));
                code++;
            }

            code <<= 1;
        }
    }
}
