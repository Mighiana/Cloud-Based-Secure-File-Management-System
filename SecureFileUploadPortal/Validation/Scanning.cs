using SecureFileUploadPortal.Data;

namespace SecureFileUploadPortal.Validation;

public enum ScanVerdict
{
    Clean,
    /// <summary>Content is not acceptable (wrong type, integrity mismatch). The object is deleted.</summary>
    Rejected,
    /// <summary>A malware signature matched. The object is kept in quarantine for review.</summary>
    Infected,
    /// <summary>The scanner could not give an answer. Treated as "not approved" and retried.</summary>
    Error,
}

public sealed record ScanResult(ScanVerdict Verdict, string Engine, string Detail)
{
    public static ScanResult Clean(string engine, string detail) => new(ScanVerdict.Clean, engine, detail);
    public static ScanResult Rejected(string engine, string detail) => new(ScanVerdict.Rejected, engine, detail);
    public static ScanResult Infected(string engine, string detail) => new(ScanVerdict.Infected, engine, detail);
    public static ScanResult Error(string engine, string detail) => new(ScanVerdict.Error, engine, detail);
}

/// <summary>The stored bytes of a file under validation, re-readable by each scanner.</summary>
public sealed class FileScanContext(FileRecord file, Func<Stream> openRead)
{
    public FileRecord File { get; } = file;
    public Stream OpenRead() => openRead();
}

/// <summary>One stage of the post-upload validation pipeline.</summary>
public interface IFileSecurityScanner
{
    string Name { get; }
    Task<ScanResult> ScanAsync(FileScanContext context, CancellationToken ct);
}
