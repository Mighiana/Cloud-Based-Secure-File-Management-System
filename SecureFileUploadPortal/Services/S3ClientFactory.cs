using Amazon;
using Amazon.Runtime;
using Amazon.S3;
using SecureFileUploadPortal.Options;

namespace SecureFileUploadPortal.Services;

public static class S3ClientFactory
{
    public static IAmazonS3 Create(StorageOptions options, bool publicEndpoint)
    {
        var config = new AmazonS3Config();
        var endpoint = publicEndpoint && !string.IsNullOrWhiteSpace(options.PublicServiceUrl)
            ? options.PublicServiceUrl
            : options.ServiceUrl;

        if (string.IsNullOrWhiteSpace(endpoint))
        {
            config.RegionEndpoint = RegionEndpoint.GetBySystemName(options.Region);
        }
        else
        {
            config.ServiceURL = endpoint;
            config.AuthenticationRegion = options.Region;
            config.ForcePathStyle = options.ForcePathStyle;
        }

        // Prefer the default credential chain (env vars, shared profile, IAM role);
        // static keys are supported for local setups and must come from user-secrets or env vars.
        return string.IsNullOrWhiteSpace(options.AccessKey)
            ? new AmazonS3Client(config)
            : new AmazonS3Client(new BasicAWSCredentials(options.AccessKey, options.SecretKey), config);
    }
}
