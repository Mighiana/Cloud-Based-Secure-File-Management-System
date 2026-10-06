using System.IO.Compression;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.Extensions.Options;
using SecureFileUploadPortal.Options;

namespace SecureFileUploadPortal.Services;

/// <summary>Reads AWS CloudTrail log files delivered to a separate audit bucket.</summary>
public class CloudTrailLogService
{
    private const int MaxListed = 5000;

    private readonly IAmazonS3 _s3;
    private readonly CloudTrailOptions _options;

    public CloudTrailLogService(IAmazonS3 s3, IOptions<CloudTrailOptions> options)
    {
        _s3 = s3;
        _options = options.Value;
    }

    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(_options.BucketName) && !string.IsNullOrWhiteSpace(_options.AccountId);

    public async Task<IReadOnlyList<StoredObject>> ListAsync(CancellationToken ct = default)
    {
        if (!IsConfigured) return [];

        var result = new List<StoredObject>();
        var request = new ListObjectsV2Request { BucketName = _options.BucketName, Prefix = _options.Prefix };
        ListObjectsV2Response response;
        do
        {
            response = await _s3.ListObjectsV2Async(request, ct);
            result.AddRange((response.S3Objects ?? [])
                .Where(o => o.Key.EndsWith(".json.gz", StringComparison.Ordinal))
                .Select(o => new StoredObject(o.Key, o.Size ?? 0, o.LastModified?.ToUniversalTime())));
            request.ContinuationToken = response.NextContinuationToken;
        } while (response.IsTruncated == true && result.Count < MaxListed);

        return result.OrderByDescending(o => o.LastModifiedUtc).ToList();
    }

    /// <summary>Only keys under the configured CloudTrail prefix can be read.</summary>
    public bool IsValidKey(string? key) =>
        IsConfigured
        && !string.IsNullOrWhiteSpace(key)
        && key.StartsWith(_options.Prefix, StringComparison.Ordinal)
        && key.EndsWith(".json.gz", StringComparison.Ordinal)
        && !key.Contains("..", StringComparison.Ordinal);

    public async Task<string> ReadAsync(string key, CancellationToken ct = default)
    {
        if (!IsValidKey(key)) throw new ArgumentException("Invalid CloudTrail log key.", nameof(key));

        using var response = await _s3.GetObjectAsync(_options.BucketName, key, ct);
        await using var gzip = new GZipStream(response.ResponseStream, CompressionMode.Decompress);
        using var reader = new StreamReader(gzip);
        return await reader.ReadToEndAsync(ct);
    }
}
