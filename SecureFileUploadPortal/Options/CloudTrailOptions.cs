namespace SecureFileUploadPortal.Options;

/// <summary>Bucket that AWS CloudTrail delivers audit logs to. Bound from the "CloudTrail" configuration section.</summary>
public class CloudTrailOptions
{
    public const string SectionName = "CloudTrail";

    public string BucketName { get; set; } = string.Empty;
    public string AccountId { get; set; } = string.Empty;

    public string Prefix => $"AWSLogs/{AccountId}/CloudTrail/";
}
