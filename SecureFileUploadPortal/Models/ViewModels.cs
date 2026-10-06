using System.ComponentModel.DataAnnotations;
using SecureFileUploadPortal.Data;

namespace SecureFileUploadPortal.Models;

public class LoginViewModel
{
    [Required, EmailAddress, Display(Name = "E-mail")]
    public string Email { get; set; } = string.Empty;

    [Required, DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    public string? ReturnUrl { get; set; }
}

public record FileRow(Guid Id, string FileName, string ContentType, long SizeBytes, DateTime UploadedAtUtc, string OwnerEmail);

public class FileListViewModel
{
    public IReadOnlyList<FileRow> Files { get; init; } = [];
    public bool ShowAllUsers { get; init; }
    public bool CanSeeAllUsers { get; init; }
}

public class UploadViewModel
{
    public int MaxFileSizeMB { get; init; }
    public IReadOnlyList<string> AllowedExtensions { get; init; } = [];
}

public class UserDashboardViewModel
{
    public string DisplayName { get; init; } = string.Empty;
    public int FileCount { get; init; }
    public long StorageBytes { get; init; }
    public DateTime? LastLoginUtc { get; init; }
    public IReadOnlyList<FileRow> RecentFiles { get; init; } = [];
    public IReadOnlyList<AuditLog> RecentActivity { get; init; } = [];
}

public record DailyActivity(string Label, int Uploads, int Downloads, int Logins, int FailedLogins);

public record UserActivity(string Email, int Events);

public class AdminDashboardViewModel
{
    public int TotalUsers { get; init; }
    public int ActiveUsers { get; init; }
    public int TotalFiles { get; init; }
    public long StorageBytes { get; init; }
    public int FailedLogins24h { get; init; }
    public int Events24h { get; init; }
    public IReadOnlyList<DailyActivity> Last7Days { get; init; } = [];
    public IReadOnlyList<AuditLog> RecentEvents { get; init; } = [];
    public IReadOnlyList<FileRow> RecentFiles { get; init; } = [];
    public IReadOnlyList<UserActivity> TopUsers { get; init; } = [];
}

public record UserRow(int Id, string Email, string DisplayName, string Role, bool IsActive, DateTime CreatedAtUtc, DateTime? LastLoginAtUtc, int FileCount, bool IsLockedOut);

public class CreateUserInput
{
    [Required, EmailAddress, StringLength(256)]
    public string Email { get; set; } = string.Empty;

    [Required, StringLength(100), Display(Name = "Display name")]
    public string DisplayName { get; set; } = string.Empty;

    [Required, DataType(DataType.Password), StringLength(128, MinimumLength = 10)]
    public string Password { get; set; } = string.Empty;

    [Required]
    public string Role { get; set; } = Roles.User;
}

public class UsersViewModel
{
    public IReadOnlyList<UserRow> Users { get; init; } = [];
    public CreateUserInput NewUser { get; init; } = new();
    public int CurrentUserId { get; init; }
}

public class AuditFilter
{
    public string? Action { get; set; }
    public string? User { get; set; }
    public bool? Succeeded { get; set; }
    public int Page { get; set; } = 1;
}

public class AuditViewModel
{
    public const int PageSize = 25;
    public IReadOnlyList<AuditLog> Entries { get; init; } = [];
    public AuditFilter Filter { get; init; } = new();
    public int TotalCount { get; init; }
    public int TotalPages => Math.Max(1, (int)Math.Ceiling(TotalCount / (double)PageSize));
    public IReadOnlyList<string> KnownActions { get; init; } = [];
}

public record CloudTrailRow(string Key, long SizeBytes, DateTime? LastModifiedUtc);

public class CloudTrailViewModel
{
    public bool IsConfigured { get; init; }
    public string? Error { get; init; }
    public IReadOnlyList<CloudTrailRow> Logs { get; init; } = [];
}

public class ReportsViewModel
{
    public long StorageBytes { get; init; }
    public int StorageQuotaMB { get; init; }
    public double StoragePercent => StorageQuotaMB <= 0 ? 0 : Math.Min(100, StorageBytes / (StorageQuotaMB * 1024.0 * 1024.0) * 100);
    public bool CloudTrailConfigured { get; init; }
}

public class SettingsViewModel
{
    public string StorageEndpoint { get; init; } = string.Empty;
    public string BucketName { get; init; } = string.Empty;
    public string Region { get; init; } = string.Empty;
    public string ServerSideEncryption { get; init; } = string.Empty;
    public bool KmsKeyConfigured { get; init; }
    public int PresignedUrlMinutes { get; init; }
    public int MaxFileSizeMB { get; init; }
    public IReadOnlyList<string> AllowedExtensions { get; init; } = [];
    public string CloudTrailBucket { get; init; } = string.Empty;
    public bool StaticCredentials { get; init; }
    public string Environment { get; init; } = string.Empty;
}
