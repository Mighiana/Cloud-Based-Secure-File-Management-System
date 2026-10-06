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

    /// <summary>Hex SHA-256 of the uploaded bytes: integrity and duplicate-detection metadata, not a signature.</summary>
    public string Sha256 { get; set; } = string.Empty;

    public FileSecurityStatus Status { get; set; } = FileSecurityStatus.Pending;
    public StorageArea StorageArea { get; set; } = StorageArea.Quarantine;
    public string? StatusReason { get; set; }
    public string? ScanEngine { get; set; }
    public DateTime? ValidatedAtUtc { get; set; }
    public DateTime? ValidationStartedAtUtc { get; set; }
    public DateTime? NextAttemptAtUtc { get; set; }
    public int ValidationAttempts { get; set; }

    /// <summary>Optimistic-concurrency token so two validators can never claim or finish the same file.</summary>
    public Guid ConcurrencyStamp { get; set; } = Guid.NewGuid();

    public bool IsDownloadable => Status == FileSecurityStatus.Approved && StorageArea == StorageArea.Approved;
}

/// <summary>Lifecycle of an upload. Only <see cref="Approved"/> files can be downloaded.</summary>
public enum FileSecurityStatus
{
    Pending,
    Validating,
    Approved,
    Rejected,
    Quarantined,
}

/// <summary>Which bucket currently holds the object.</summary>
public enum StorageArea
{
    Quarantine,
    Approved,
}

public static class AuditActions
{
    public const string LoginSucceeded = "LoginSucceeded";
    public const string LoginFailed = "LoginFailed";
    public const string LoginLockedOut = "LoginLockedOut";
    public const string Logout = "Logout";
    public const string AccessDenied = "AccessDenied";
    public const string FileUploadReceived = "FileUploadReceived";
    public const string FileUploadRejected = "FileUploadRejected";
    public const string FileUploadFailed = "FileUploadFailed";
    public const string FileDownloaded = "FileDownloaded";
    public const string FileDeleted = "FileDeleted";
    public const string DownloadBlockedSecurityState = "DownloadBlockedSecurityState";
    public const string FileValidationStarted = "FileValidationStarted";
    public const string FileValidationApproved = "FileValidationApproved";
    public const string FileValidationRejected = "FileValidationRejected";
    public const string FileScanFailed = "FileScanFailed";
    public const string FileQuarantined = "FileQuarantined";
    public const string FileRescanRequested = "FileRescanRequested";
    public const string UserCreated = "UserCreated";
    public const string UserRoleChanged = "UserRoleChanged";
    public const string UserActivated = "UserActivated";
    public const string UserDeactivated = "UserDeactivated";
    public const string CloudTrailLogViewed = "CloudTrailLogViewed";
    public const string ReportExported = "ReportExported";
    public const string AuditChainVerified = "AuditChainVerified";
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

    /// <summary>File the event refers to, if any (no FK, so history outlives the file).</summary>
    public Guid? FileId { get; set; }

    /// <summary>Tamper-evident hash chain; null on rows written before the chain existed.</summary>
    public string? PreviousHash { get; set; }
    public string? EntryHash { get; set; }
}
