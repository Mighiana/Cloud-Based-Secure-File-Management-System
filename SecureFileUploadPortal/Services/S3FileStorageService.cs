using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Options;
using SecureFileUploadPortal.Options;

namespace SecureFileUploadPortal.Services;

public class S3FileStorageService : IFileStorageService
{
    private readonly IAmazonS3 _s3;
    private readonly IAmazonS3 _presigner;
    private readonly StorageOptions _options;

    /// <param name="presigner">Client configured with the browser-facing endpoint; only used to sign URLs (no network calls).</param>
    public S3FileStorageService(IAmazonS3 s3, IAmazonS3 presigner, IOptions<StorageOptions> options)
    {
        _s3 = s3;
        _presigner = presigner;
        _options = options.Value;
    }

    public async Task<string> UploadAsync(Stream content, string originalFileName, string contentType, CancellationToken ct = default)
    {
        // Random object key: user-supplied names never become S3 paths.
        var key = $"{Guid.NewGuid():N}{Path.GetExtension(originalFileName).ToLowerInvariant()}";
        var request = new PutObjectRequest
        {
            BucketName = _options.BucketName,
            Key = key,
            InputStream = content,
            ContentType = string.IsNullOrWhiteSpace(contentType) ? "application/octet-stream" : contentType,
        };

        switch (_options.ServerSideEncryption)
        {
            case "aws:kms":
                request.ServerSideEncryptionMethod = ServerSideEncryptionMethod.AWSKMS;
                if (!string.IsNullOrWhiteSpace(_options.KmsKeyId))
                    request.ServerSideEncryptionKeyManagementServiceKeyId = _options.KmsKeyId;
                break;
            case "AES256":
                request.ServerSideEncryptionMethod = ServerSideEncryptionMethod.AES256;
                break;
        }

        await _s3.PutObjectAsync(request, ct);
        return key;
    }

    public async Task<IReadOnlyList<StoredObject>> ListAsync(CancellationToken ct = default)
    {
        var result = new List<StoredObject>();
        var request = new ListObjectsV2Request { BucketName = _options.BucketName };
        ListObjectsV2Response response;
        do
        {
            response = await _s3.ListObjectsV2Async(request, ct);
            foreach (var o in response.S3Objects ?? [])
                result.Add(new StoredObject(o.Key, o.Size ?? 0, o.LastModified?.ToUniversalTime()));
            request.ContinuationToken = response.NextContinuationToken;
        } while (response.IsTruncated == true);

        return result;
    }

    public Task DeleteAsync(string key, CancellationToken ct = default) =>
        _s3.DeleteObjectAsync(_options.BucketName, key, ct);

    public string GetDownloadUrl(string key, string downloadFileName)
    {
        var request = new GetPreSignedUrlRequest
        {
            BucketName = _options.BucketName,
            Key = key,
            Verb = HttpVerb.GET,
            Expires = DateTime.UtcNow.AddMinutes(_options.PresignedUrlMinutes),
            Protocol = BrowserEndpoint(_options).StartsWith("http://", StringComparison.OrdinalIgnoreCase) ? Protocol.HTTP : Protocol.HTTPS,
        };
        request.ResponseHeaderOverrides.ContentDisposition =
            $"attachment; filename=\"{SanitizeHeaderFileName(downloadFileName)}\"";
        return _presigner.GetPreSignedURL(request);
    }

    public async Task<long> GetTotalSizeBytesAsync(CancellationToken ct = default) =>
        (await ListAsync(ct)).Sum(o => o.SizeBytes);

    internal static string BrowserEndpoint(StorageOptions o) =>
        !string.IsNullOrWhiteSpace(o.PublicServiceUrl) ? o.PublicServiceUrl : o.ServiceUrl ?? string.Empty;

    internal static string SanitizeHeaderFileName(string name)
    {
        var cleaned = new string(name.Where(c => c >= 0x20 && c < 0x7f && c != '"' && c != '\\').ToArray());
        return string.IsNullOrWhiteSpace(cleaned) ? "download" : cleaned;
    }
}
