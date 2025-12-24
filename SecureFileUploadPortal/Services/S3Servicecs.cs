using Amazon;
using Amazon.S3;
using Amazon.S3.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System.IO.Compression;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;

namespace SecureFileUploadPortal.Services
{
    public class S3Service
    {
        private readonly IAmazonS3 _s3Client;
        private readonly string _bucketName;
        private readonly ILogger<S3Service> _logger;
        private readonly List<string> _alerts = new();
        public S3Service(IConfiguration config, ILogger<S3Service> logger)
        {
            _logger = logger;
            _bucketName = config["AWS:BucketName"] ?? throw new ArgumentNullException("AWS:BucketName missing");
            var accessKey = config["AWS:AccessKey"] ?? throw new ArgumentNullException("AWS:AccessKey missing");
            var secretKey = config["AWS:SecretKey"] ?? throw new ArgumentNullException("AWS:SecretKey missing");
            var region = config["AWS:Region"] ?? throw new ArgumentNullException("AWS:Region missing");
            _s3Client = new AmazonS3Client(accessKey, secretKey, RegionEndpoint.GetBySystemName(region));
        }
        // Alerts
        public void AddAlert(string message)
        {
            if (!_alerts.Contains(message))
                _alerts.Add(message);
        }
        public List<string> GetAlerts() => _alerts.ToList();
        public void ClearAlerts() => _alerts.Clear();
        // File operations
        public async Task UploadFileAsync(IFormFile file)
        {
            var key = Guid.NewGuid() + Path.GetExtension(file.FileName);
            using var stream = file.OpenReadStream();
            var request = new PutObjectRequest
            {
                BucketName = _bucketName,
                Key = key,
                InputStream = stream,
                ServerSideEncryptionMethod = ServerSideEncryptionMethod.AWSKMS
            };
            try
            {
                await _s3Client.PutObjectAsync(request);
                AddAlert($"File uploaded: {file.FileName}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Upload failed for {FileName}", file.FileName);
                File.AppendAllText("errors.log", $"{DateTime.Now}: Upload failed - {ex.Message}\n");
                throw;
            }
        }
        public async Task DeleteFileAsync(string key)
        {
            try
            {
                await _s3Client.DeleteObjectAsync(_bucketName, key);
                AddAlert($"File deleted: {key}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Delete failed for {Key}", key);
                File.AppendAllText("errors.log", $"{DateTime.Now}: Delete failed - {ex.Message}\n");
                throw;
            }
        }
        public async Task<List<string>> ListFilesAsync()
        {
            try
            {
                var response = await _s3Client.ListObjectsV2Async(new ListObjectsV2Request { BucketName = _bucketName });
                return response.S3Objects.Select(o => o.Key).ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ListFiles failed");
                File.AppendAllText("errors.log", $"{DateTime.Now}: ListFiles failed - {ex.Message}\n");
                return new List<string>();
            }
        }
        public string GetPreSignedURL(string key)
        {
            try
            {
                return _s3Client.GetPreSignedURL(new GetPreSignedUrlRequest
                {
                    BucketName = _bucketName,
                    Key = key,
                    Expires = DateTime.UtcNow.AddMinutes(15)
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GetPreSignedURL failed for {Key}", key);
                File.AppendAllText("errors.log", $"{DateTime.Now}: GetPreSignedURL failed - {ex.Message}\n");
                return string.Empty;
            }
        }
        public async Task<long> GetTotalStorageSizeAsync()
        {
            long totalSizeBytes = 0;

            var request = new ListObjectsV2Request
            {
                BucketName = "secure-file-upload-portal" // replace with your actual bucket
            };

            ListObjectsV2Response response;
            do
            {
                response = await _s3Client.ListObjectsV2Async(request);

                foreach (var obj in response.S3Objects)
                {
                    totalSizeBytes += obj.Size ?? 0; // ✅ safely handle nullable long
                }

                request.ContinuationToken = response.NextContinuationToken;

            } while (response.IsTruncated ?? false); // ✅ safely handle nullable bool

            long totalSizeMB = totalSizeBytes / (1024 * 1024);
            return totalSizeMB;
        }

        // CloudTrail logs
        public async Task<List<string>> ListAuditLogsAsync(string auditBucket, string accountId)
        {
            try
            {
                string prefix = $"AWSLogs/{accountId}/CloudTrail/";
                var response = await _s3Client.ListObjectsV2Async(new ListObjectsV2Request
                {
                    BucketName = auditBucket,
                    Prefix = prefix
                });
                return response.S3Objects
                    .Where(o => o.Key.EndsWith(".json.gz"))
                    .OrderByDescending(o => o.LastModified)
                    .Select(o => o.Key)
                    .ToList();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ListAuditLogs failed for {Bucket} {AccountId}", auditBucket, accountId);
                File.AppendAllText("errors.log", $"{DateTime.Now}: ListAuditLogs failed - {ex.Message}\n");
                return new List<string>();
            }
        }
        public async Task<string> GetAuditLogContentAsync(string auditBucket, string key)
        {
            try
            {
                var response = await _s3Client.GetObjectAsync(auditBucket, key);
                using var gzip = new GZipStream(response.ResponseStream, CompressionMode.Decompress);
                using var reader = new StreamReader(gzip);
                return await reader.ReadToEndAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GetAuditLogContent failed for {Key}", key);
                File.AppendAllText("errors.log", $"{DateTime.Now}: GetAuditLogContent failed - {ex.Message}\n");
                return string.Empty;
            }
        }
        public async Task<int> GetTotalFilesAsync()
        {
            try
            {
                var response = await _s3Client.ListObjectsV2Async(new ListObjectsV2Request
                {
                    BucketName = _bucketName
                });
                return response.S3Objects.Count;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GetTotalFiles failed");
                File.AppendAllText("errors.log", $"{DateTime.Now}: GetTotalFiles failed - {ex.Message}\n");
                return 0;
            }
        }
        public async Task<long> GetTotalLogsAsync(string auditBucket, string accountId)
        {
            try
            {
                string prefix = $"AWSLogs/{accountId}/CloudTrail/";
                var response = await _s3Client.ListObjectsV2Async(new ListObjectsV2Request
                {
                    BucketName = auditBucket,
                    Prefix = prefix
                });
                return response.S3Objects.Count; // Or sum sizes if needed
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "GetTotalLogs failed for {Bucket} {AccountId}", auditBucket, accountId);
                File.AppendAllText("errors.log", $"{DateTime.Now}: GetTotalLogs failed - {ex.Message}\n");
                return 0;
            }
        }
    }
}