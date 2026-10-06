using System.Globalization;
using System.Text;

namespace SecureFileUploadPortal.Services;

/// <summary>Minimal RFC 4180 CSV writer that also neutralises spreadsheet formula injection.</summary>
public class CsvBuilder
{
    private readonly StringBuilder _sb = new();

    public CsvBuilder Row(params object?[] values)
    {
        _sb.AppendLine(string.Join(',', values.Select(Escape)));
        return this;
    }

    public byte[] ToBytes() => Encoding.UTF8.GetPreamble().Concat(Encoding.UTF8.GetBytes(_sb.ToString())).ToArray();

    public override string ToString() => _sb.ToString();

    internal static string Escape(object? value)
    {
        var s = value switch
        {
            null => string.Empty,
            DateTime d => d.ToString("yyyy-MM-dd HH:mm:ss'Z'", CultureInfo.InvariantCulture),
            IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
            _ => value.ToString() ?? string.Empty,
        };

        if (s.Length > 0 && "=+-@\t\r".Contains(s[0])) s = "'" + s;
        return s.IndexOfAny([',', '"', '\n', '\r']) >= 0 ? $"\"{s.Replace("\"", "\"\"")}\"" : s;
    }
}
