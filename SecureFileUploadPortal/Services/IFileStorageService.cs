using SecureFileUploadPortal.Data;

namespace SecureFileUploadPortal.Services;

public record StoredObject(string Key, long SizeBytes, DateTime? LastModifiedUtc);

/// <summary>
/// Object storage split into a quarantine area (all new uploads) and an approved area (validated files).
/// Download URLs can only be issued for the approved area.
/// </summary>
public interface IFileStorageService
{
    /// <summary>Uploads the stream to quarantine under a new random key and returns that key.</summary>
    Task<string> UploadToQuarantineAsync(Stream content, string originalFileName, string contentType, CancellationToken ct = default);

    /// <summary>Copies a quarantined object to the approved area (same key). Safe to repeat.</summary>
    Task CopyToApprovedAsync(string key, string contentType, CancellationToken ct = default);

    /// <summary>Downloads a quarantined object into <paramref name="destination"/> for validation.</summary>
    Task ReadQuarantinedAsync(string key, Stream destination, CancellationToken ct = default);

    Task DeleteAsync(StorageArea area, string key, CancellationToken ct = default);

    /// <summary>Short-lived pre-signed GET for an approved object.</summary>
    string GetApprovedDownloadUrl(string key, string downloadFileName);
}
