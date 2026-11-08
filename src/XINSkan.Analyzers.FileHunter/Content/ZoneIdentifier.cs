using System.Text;

namespace XINSkan.Analyzers.FileHunter.Content;

/// <summary>
/// Mark of the Web: the Zone.Identifier alternate stream that browsers and archivers attach to downloaded files.
/// It records where a file came from; it is file metadata, not browsing history.
/// </summary>
public sealed record ZoneInfo(int? ZoneId, string? HostUrl, string? ReferrerUrl)
{
    public string ZoneName => ZoneId switch
    {
        0 => "Локальный компьютер",
        1 => "Локальная сеть",
        2 => "Надёжные сайты",
        3 => "Интернет",
        4 => "Ограниченные сайты",
        null => "не указана",
        _ => $"зона {ZoneId}",
    };

    public const int MaxBytes = 8192;

    public static ZoneInfo? Parse(ReadOnlySpan<byte> raw)
    {
        if (raw.IsEmpty)
        {
            return null;
        }

        string text;
        if (raw.Length >= 2 && raw[0] == 0xFF && raw[1] == 0xFE)
        {
            text = Encoding.Unicode.GetString(raw[2..]);
        }
        else
        {
            text = Encoding.UTF8.GetString(raw).TrimStart('﻿');
        }

        int? zone = null;
        string? host = null, referrer = null;
        var inSection = false;
        foreach (var raw2 in text.Split('\n'))
        {
            var line = raw2.Trim().TrimEnd('\0');
            if (line.StartsWith('['))
            {
                inSection = line.Equals("[ZoneTransfer]", StringComparison.OrdinalIgnoreCase);
                continue;
            }

            if (!inSection)
            {
                continue;
            }

            var eq = line.IndexOf('=', StringComparison.Ordinal);
            if (eq <= 0)
            {
                continue;
            }

            var key = line[..eq].Trim();
            var value = line[(eq + 1)..].Trim();
            if (key.Equals("ZoneId", StringComparison.OrdinalIgnoreCase) && int.TryParse(value, System.Globalization.CultureInfo.InvariantCulture, out var z))
            {
                zone = z;
            }
            else if (key.Equals("HostUrl", StringComparison.OrdinalIgnoreCase) && value.Length > 0)
            {
                host = value;
            }
            else if (key.Equals("ReferrerUrl", StringComparison.OrdinalIgnoreCase) && value.Length > 0)
            {
                referrer = value;
            }
        }

        return zone is null && host is null && referrer is null ? null : new ZoneInfo(zone, host, referrer);
    }
}
