namespace SecureFileUploadPortal.Data;

public static class Roles
{
    public const string Admin = "Admin";
    public const string User = "User";
    public static readonly string[] All = [Admin, User];
}

public class AppUser
{
    public int Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string PasswordHash { get; set; } = string.Empty;
    public string Role { get; set; } = Roles.User;
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAtUtc { get; set; }
    public int FailedLoginCount { get; set; }
    public DateTime? LockoutEndUtc { get; set; }

    /// <summary>Rotated whenever role, status or password changes; invalidates existing auth cookies.</summary>
    public string SecurityStamp { get; set; } = Guid.NewGuid().ToString("N");

    public List<FileRecord> Files { get; set; } = [];
}

public class FileRecord
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string StorageKey { get; set; } = string.Empty;
    public string OriginalFileName { get; set; } = string.Empty;
    public string ContentType { get; set; } = string.Empty;
    public long SizeBytes { get; set; }
    public DateTime UploadedAtUtc { get; set; } = DateTime.UtcNow;

    public int OwnerId { get; set; }
    public AppUser Owner { get; set; } = null!;
}

public static class AuditActions
{
    public const string LoginSucceeded = "LoginSucceeded";
    public const string LoginFailed = "LoginFailed";
    public const string LoginLockedOut = "LoginLockedOut";
    public const string Logout = "Logout";
    public const string AccessDenied = "AccessDenied";
    public const string FileUploaded = "FileUploaded";
    public const string FileUploadRejected = "FileUploadRejected";
    public const string FileUploadFailed = "FileUploadFailed";
    public const string FileDownloaded = "FileDownloaded";
    public const string FileDeleted = "FileDeleted";
    public const string UserCreated = "UserCreated";
    public const string UserRoleChanged = "UserRoleChanged";
    public const string UserActivated = "UserActivated";
    public const string UserDeactivated = "UserDeactivated";
    public const string CloudTrailLogViewed = "CloudTrailLogViewed";
    public const string ReportExported = "ReportExported";
}

public class AuditLog
{
    public long Id { get; set; }
    public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
    public int? UserId { get; set; }

    /// <summary>Snapshot of the acting identity, kept even if the user row changes.</summary>
    public string UserEmail { get; set; } = string.Empty;
    public string Action { get; set; } = string.Empty;
    public string? Target { get; set; }
    public string? Details { get; set; }
    public string? IpAddress { get; set; }
    public bool Succeeded { get; set; }
}
