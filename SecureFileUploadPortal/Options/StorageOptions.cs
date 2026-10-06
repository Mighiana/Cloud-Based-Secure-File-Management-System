namespace SecureFileUploadPortal.Options;

/// <summary>S3 buckets that store uploaded files. Bound from the "Storage" configuration section.</summary>
public class StorageOptions
{
    public const string SectionName = "Storage";

    public string Region { get; set; } = "eu-central-1";

    /// <summary>Receives every upload. The web app can write and delete here but never presigns from it.</summary>
    public string QuarantineBucketName { get; set; } = string.Empty;

    /// <summary>Holds files that passed validation; the only bucket download links are issued for.</summary>
    public string ApprovedBucketName { get; set; } = string.Empty;

    /// <summary>Optional S3-compatible endpoint (e.g. MinIO for local development). Leave empty for AWS.</summary>
    public string? ServiceUrl { get; set; }
    public bool ForcePathStyle { get; set; }

    /// <summary>Endpoint browsers use for presigned download links when it differs from ServiceUrl (e.g. MinIO inside Docker).</summary>
    public string? PublicServiceUrl { get; set; }

    /// <summary>"AES256" (SSE-S3, no extra cost), "aws:kms" (SSE-KMS) or "None" (rely on the bucket default).</summary>
    public string ServerSideEncryption { get; set; } = "AES256";
    public string? KmsKeyId { get; set; }

    public int PresignedUrlMinutes { get; set; } = 15;

    /// <summary>Storage budget shown on the Reports page. Informational only; not enforced.</summary>
    public int StorageQuotaMB { get; set; } = 1000;

    /// <summary>Optional static credentials. When empty the AWS default credential chain is used (env vars, profile, IAM role).</summary>
    public string? AccessKey { get; set; }
    public string? SecretKey { get; set; }
}
