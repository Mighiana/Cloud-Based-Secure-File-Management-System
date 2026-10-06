using System.Security.Cryptography;
using SecureFileUploadPortal.Services;

namespace SecureFileUploadPortal.Validation;

/// <summary>
/// Always-on checks against the bytes actually stored in quarantine: size and SHA-256 must match what the
/// upload recorded, and the file signature must match the extension.
/// </summary>
public sealed class BasicFileValidationScanner : IFileSecurityScanner
{
    public string Name => "basic-validation";

    public async Task<ScanResult> ScanAsync(FileScanContext context, CancellationToken ct)
    {
        var file = context.File;
        await using var stream = context.OpenRead();

        if (stream.Length != file.SizeBytes)
            return ScanResult.Rejected(Name, $"stored size {stream.Length} B differs from uploaded size {file.SizeBytes} B");

        var header = await FileSignatures.ReadHeaderAsync(stream, ct);
        if (FileSignatures.Check(Path.GetExtension(file.OriginalFileName), header) is { } problem)
            return ScanResult.Rejected(Name, problem);

        stream.Position = 0;
        var sha256 = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct)).ToLowerInvariant();
        if (!string.Equals(sha256, file.Sha256, StringComparison.OrdinalIgnoreCase))
            return ScanResult.Rejected(Name, "SHA-256 of the stored object differs from the uploaded file");

        return ScanResult.Clean(Name, "size, SHA-256 and file signature verified");
    }
}
