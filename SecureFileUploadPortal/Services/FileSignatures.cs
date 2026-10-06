namespace SecureFileUploadPortal.Services;

/// <summary>
/// Magic-byte checks for the allow-listed file types. Deliberately small: it proves the content is the
/// claimed type, it does not parse documents.
/// </summary>
public static class FileSignatures
{
    public const int HeaderLength = 8192;

    private static readonly byte[] Pdf = "%PDF-"u8.ToArray();
    private static readonly byte[] Png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    private static readonly byte[] Jpeg = [0xFF, 0xD8, 0xFF];
    private static readonly byte[] Zip = [0x50, 0x4B, 0x03, 0x04];

    private static readonly Dictionary<string, byte[]> Expected = new(StringComparer.OrdinalIgnoreCase)
    {
        [".pdf"] = Pdf,
        [".png"] = Png,
        [".jpg"] = Jpeg,
        [".jpeg"] = Jpeg,
        [".docx"] = Zip,
        [".xlsx"] = Zip,
    };

    private static readonly (byte[] Magic, string Name)[] Known =
    [
        ("MZ"u8.ToArray(), "a Windows executable (MZ header)"),
        ([0x7F, 0x45, 0x4C, 0x46], "an ELF executable"),
        ([0xCF, 0xFA, 0xED, 0xFE], "a Mach-O executable"),
        ("#!"u8.ToArray(), "a script (#! header)"),
        (Pdf, "a PDF document"),
        (Png, "a PNG image"),
        (Jpeg, "a JPEG image"),
        (Zip, "a ZIP-based file"),
    ];

    /// <summary>Extensions this class can verify; anything else must not be allow-listed.</summary>
    public static IReadOnlyCollection<string> SupportedExtensions { get; } = [.. Expected.Keys, ".txt"];

    /// <summary>Returns a rejection reason, or null when the header matches the extension.</summary>
    public static string? Check(string extension, ReadOnlySpan<byte> header)
    {
        extension = extension.ToLowerInvariant();
        if (extension == ".txt")
        {
            if (Describe(header) is { } kind && kind.Contains("executable")) return $"content is {kind}, not text";
            return header.IndexOf((byte)0) >= 0 ? "binary content in a .txt file" : null;
        }

        if (!Expected.TryGetValue(extension, out var magic))
            return $"no signature check is defined for '{extension}'";

        if (header.StartsWith(magic)) return null;
        return Describe(header) is { } actual
            ? $"content is {actual}, not a {extension} file"
            : $"content does not match the {extension} file signature";
    }

    private static string? Describe(ReadOnlySpan<byte> header)
    {
        foreach (var (magic, name) in Known)
            if (header.StartsWith(magic)) return name;
        return null;
    }

    public static async Task<byte[]> ReadHeaderAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new byte[HeaderLength];
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read), ct);
            if (n == 0) break;
            read += n;
        }
        return buffer[..read];
    }
}
