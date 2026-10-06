using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Options;
using SecureFileUploadPortal.Data;
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

    public async Task<string> UploadToQuarantineAsync(Stream content, string originalFileName, string contentType, CancellationToken ct = default)
    {
        // Random object key: user-supplied names never become S3 paths.
        var key = $"{Guid.NewGuid():N}{Path.GetExtension(originalFileName).ToLowerInvariant()}";
        var request = new PutObjectRequest
        {
            BucketName = _options.QuarantineBucketName,
            Key = key,
            InputStream = content,
            ContentType = string.IsNullOrWhiteSpace(contentType) ? "application/octet-stream" : contentType,
        };
        (request.ServerSideEncryptionMethod, request.ServerSideEncryptionKeyManagementServiceKeyId) = Encryption();
        await _s3.PutObjectAsync(request, ct);
        return key;
    }

    public async Task CopyToApprovedAsync(string key, string contentType, CancellationToken ct = default)
    {
        var request = new CopyObjectRequest
        {
            SourceBucket = _options.QuarantineBucketName,
            SourceKey = key,
            DestinationBucket = _options.ApprovedBucketName,
            DestinationKey = key,
            ContentType = contentType,
            MetadataDirective = S3MetadataDirective.REPLACE,
        };
        (request.ServerSideEncryptionMethod, request.ServerSideEncryptionKeyManagementServiceKeyId) = Encryption();
        await _s3.CopyObjectAsync(request, ct);
    }

    public async Task ReadQuarantinedAsync(string key, Stream destination, CancellationToken ct = default)
    {
        using var response = await _s3.GetObjectAsync(_options.QuarantineBucketName, key, ct);
        await response.ResponseStream.CopyToAsync(destination, ct);
    }

    public Task DeleteAsync(StorageArea area, string key, CancellationToken ct = default) =>
        _s3.DeleteObjectAsync(Bucket(area), key, ct);

    public string GetApprovedDownloadUrl(string key, string downloadFileName)
    {
        var request = new GetPreSignedUrlRequest
        {
            BucketName = _options.ApprovedBucketName,
            Key = key,
            Verb = HttpVerb.GET,
            Expires = DateTime.UtcNow.AddMinutes(_options.PresignedUrlMinutes),
            Protocol = BrowserEndpoint(_options).StartsWith("http://", StringComparison.OrdinalIgnoreCase) ? Protocol.HTTP : Protocol.HTTPS,
        };
        request.ResponseHeaderOverrides.ContentDisposition =
            $"attachment; filename=\"{SanitizeHeaderFileName(downloadFileName)}\"";
        return _presigner.GetPreSignedURL(request);
    }

    private string Bucket(StorageArea area) =>
        area == StorageArea.Approved ? _options.ApprovedBucketName : _options.QuarantineBucketName;

    /// <summary>Per-request SSE settings; "None" leaves encryption to the bucket default.</summary>
    private (ServerSideEncryptionMethod?, string?) Encryption() => _options.ServerSideEncryption switch
    {
        "aws:kms" => (ServerSideEncryptionMethod.AWSKMS, string.IsNullOrWhiteSpace(_options.KmsKeyId) ? null : _options.KmsKeyId),
        "AES256" => (ServerSideEncryptionMethod.AES256, null),
        _ => (null, null),
    };

    internal static string BrowserEndpoint(StorageOptions o) =>
        !string.IsNullOrWhiteSpace(o.PublicServiceUrl) ? o.PublicServiceUrl : o.ServiceUrl ?? string.Empty;

    internal static string SanitizeHeaderFileName(string name)
    {
        var cleaned = new string(name.Where(c => c >= 0x20 && c < 0x7f && c != '"' && c != '\\').ToArray());
        return string.IsNullOrWhiteSpace(cleaned) ? "download" : cleaned;
    }
}
