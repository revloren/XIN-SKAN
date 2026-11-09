namespace XINSkan.Ntfs;

/// <summary>Content of a file read from the volume through its MFT record, with what could not be read.</summary>
public sealed record NtfsFileContent(FileReference Reference, byte[] Data, long DeclaredSize, IReadOnlyList<string> Problems)
{
    public bool Complete => Problems.Count == 0 && Data.Length == DeclaredSize;
}

/// <summary>
/// Reads the unnamed $DATA of a file directly from the volume, following its data runs (and the extension
/// records of a fragmented file). This is how files that Windows keeps open exclusively — registry hives such as
/// Amcache.hve, NTUSER.DAT of other users — are read without copying them or asking a service to.
/// </summary>
public static class NtfsFile
{
    public static NtfsFileContent? Read(MftReader reader, FileReference reference, long maxBytes)
    {
        ArgumentNullException.ThrowIfNull(reader);
        var problems = new List<string>();
        var raw = reader.ReadRecord(reference.Entry);
        if (raw is null)
        {
            return null;
        }

        var record = MftRecord.Parse(raw, reference.Entry, includeRuns: true, maxResidentBytes: int.MaxValue);
        if (record.State != MftRecordState.Parsed || record.Sequence != reference.Sequence)
        {
            return null; // the record now belongs to another file
        }

        var segments = record.Data.Where(d => d.Name.Length == 0).ToList();
        if (record.AttributeList is { } list)
        {
            foreach (var e in list.Where(e => e.Type == MftRecord.TypeData && e.Name.Length == 0 && e.Record.Entry != reference.Entry))
            {
                var ext = reader.ReadRecord(e.Record.Entry);
                var parsed = ext is null ? null : MftRecord.Parse(ext, e.Record.Entry, includeRuns: true);
                var segment = parsed?.Data.FirstOrDefault(d => d.Name.Length == 0 && d.StartVcn == e.StartVcn);
                if (segment is null || parsed!.BaseRecord.Entry != reference.Entry)
                {
                    problems.Add($"Продолжение данных в записи {e.Record.Entry} не прочитано.");
                    continue;
                }

                segments.Add(segment);
            }
        }
        else if (record.HasNonResidentAttributeList)
        {
            problems.Add("Список атрибутов файла вынесен за пределы записи; данные прочитаны только из основной записи.");
        }

        var first = segments.FirstOrDefault(s => s.StartVcn == 0);
        if (first is null)
        {
            problems.Add("У файла нет основного потока данных.");
            return new NtfsFileContent(reference, [], 0, problems);
        }

        if (!first.NonResident)
        {
            var value = first.ResidentValue ?? [];
            return new NtfsFileContent(reference, value, value.Length, problems);
        }

        if (first.IsCompressed || first.IsEncrypted)
        {
            problems.Add(first.IsEncrypted ? "Файл зашифрован (EFS)." : "Файл сжат средствами NTFS; такие файлы не читаются напрямую.");
            return new NtfsFileContent(reference, [], first.Size, problems);
        }

        var size = first.Size;
        if (size > maxBytes || size < 0)
        {
            problems.Add($"Файл {size} байт больше предела {maxBytes}.");
            return new NtfsFileContent(reference, [], size, problems);
        }

        var cluster = reader.Boot.BytesPerCluster;
        var data = new byte[size];
        long filled = 0;
        foreach (var s in segments.Where(s => s.NonResident && s.Runs is not null).OrderBy(s => s.StartVcn))
        {
            var vcn = s.StartVcn;
            foreach (var run in s.Runs!)
            {
                var at = vcn * cluster;
                var length = run.Length * cluster;
                vcn += run.Length;
                if (at >= size)
                {
                    break;
                }

                var take = (int)Math.Min(length, size - at);
                if (run.Lcn is { } lcn)
                {
                    var got = reader.ReadVolume(lcn * cluster, data.AsSpan((int)at, take));
                    if (got < take)
                    {
                        problems.Add($"Кластеры с {lcn} прочитаны не полностью ({got} из {take} байт).");
                    }
                }

                filled = Math.Max(filled, at + take); // sparse runs stay zero
            }
        }

        if (filled < size)
        {
            problems.Add($"Цепочка кластеров покрывает {filled} из {size} байт.");
        }

        return new NtfsFileContent(reference, data, size, problems);
    }
}
