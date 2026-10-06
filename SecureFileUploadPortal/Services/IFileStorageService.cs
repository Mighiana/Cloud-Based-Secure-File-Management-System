namespace SecureFileUploadPortal.Services;

public record StoredObject(string Key, long SizeBytes, DateTime? LastModifiedUtc);

/// <summary>Object storage for uploaded files.</summary>
public interface IFileStorageService
{
    /// <summary>Uploads the stream under a new random key and returns that key.</summary>
    Task<string> UploadAsync(Stream content, string originalFileName, string contentType, CancellationToken ct = default);
    Task<IReadOnlyList<StoredObject>> ListAsync(CancellationToken ct = default);
    Task DeleteAsync(string key, CancellationToken ct = default);
    string GetDownloadUrl(string key, string downloadFileName);
    Task<long> GetTotalSizeBytesAsync(CancellationToken ct = default);
}
