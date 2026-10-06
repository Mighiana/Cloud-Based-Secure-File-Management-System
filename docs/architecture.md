# Architecture

This document describes the application as implemented in this repository. Anything
configured only in the AWS console (see [Project history](../README.md#project-history))
is called out separately.

## High-level flow

```mermaid
flowchart LR
    U([User / Browser]) -->|HTTPS| APP[ASP.NET Core 8 MVC]
    APP --> AUTH{Cookie auth +<br/>Admin / User roles}
    AUTH -->|file bytes| S3[(Amazon S3<br/>SSE-KMS / SSE-S3)]
    AUTH -->|users, file metadata| SQL[(SQL Server<br/>EF Core)]
    AUTH -->|every security-relevant action| AUDIT[[AuditLogs table]]
    AUDIT --- SQL
    CT[(CloudTrail bucket)] -.->|read-only, admins| APP
```

### Upload-scan Lambda (2025 console build, reconstructed as code in 2026)

```mermaid
flowchart LR
    S3[(Files bucket)] -->|ObjectCreated| L[AWS Lambda<br/>simulated scan]
    L -->|scan result| SNS[[SNS topic<br/>FileUploadAlerts]]
    SNS -->|e-mail| SUB([Subscribers])
```

The coursework deployment had an S3-triggered Lambda that performed a basic (simulated) check
on each upload and sent "scan successful / failed" e-mails through SNS. It was built in the AWS
console and its original code was never committed. [`lambda/upload-scan`](../lambda/upload-scan)
is a 2026 reconstruction (size / extension / file-signature checks, `scan-status` object tags,
SNS e-mail) with Terraform in [`deploy/aws/upload-scan`](../deploy/aws/upload-scan). It runs
independently of the web application, which does not read the tags.

## Components

```mermaid
flowchart TB
    subgraph Browser
        UI[Razor views + Bootstrap 5]
    end

    subgraph App["ASP.NET Core 8 MVC (SecureFileUploadPortal)"]
        MW["Middleware<br/>security headers · HSTS · rate limiter ·<br/>authentication · authorization"]
        AC[AccountController<br/>login / logout / access denied]
        HC[HomeController<br/>per-user dashboard]
        FC[FileController<br/>upload / list / download / delete]
        ADC["AdminController [Authorize(Roles=Admin)]<br/>dashboard · users · audit · CloudTrail · reports · config"]
        US[UserService<br/>PBKDF2 hashing · lockout]
        AS[AuditService]
        UV[UploadValidator]
        FS[S3FileStorageService]
        CTS[CloudTrailLogService]
        DB[(AppDbContext)]
    end

    UI --> MW --> AC & HC & FC & ADC
    AC --> US --> DB
    FC --> UV
    FC --> FS --> S3[(S3 file bucket)]
    FC --> DB
    ADC --> DB
    ADC --> CTS --> CTB[(CloudTrail bucket)]
    AC & FC & ADC --> AS --> DB
    DB --> SQL[(SQL Server)]
```

| Layer | Implementation |
|---|---|
| Presentation | Razor views, Bootstrap 5, Font Awesome, Chart.js (admin activity chart only) |
| Web / security | Cookie authentication, global "authenticated user" fallback policy, `[Authorize(Roles = "Admin")]`, global antiforgery validation, fixed-window rate limit on login, security headers |
| Domain services | `UserService`, `AuditService`, `UploadValidator`, `FileAccessPolicy`, `CsvBuilder` |
| Persistence | EF Core 8 + SQL Server, code-first migrations in `Data/Migrations` |
| Object storage | AWS SDK for .NET (`AWSSDK.S3`), any S3-compatible endpoint for local dev |

## Data model

```mermaid
erDiagram
    Users ||--o{ FileRecords : owns
    Users {
        int Id PK
        nvarchar Email UK "normalised lower-case"
        nvarchar DisplayName
        nvarchar PasswordHash "ASP.NET Core Identity PBKDF2"
        nvarchar Role "Admin | User"
        bit IsActive
        int FailedLoginCount
        datetime2 LockoutEndUtc
        nvarchar SecurityStamp "rotated on role/status change"
        datetime2 CreatedAtUtc
        datetime2 LastLoginAtUtc
    }
    FileRecords {
        uniqueidentifier Id PK
        nvarchar StorageKey UK "random S3 key"
        nvarchar OriginalFileName
        nvarchar ContentType "derived from extension"
        bigint SizeBytes
        datetime2 UploadedAtUtc
        int OwnerId FK
    }
    AuditLogs {
        bigint Id PK
        datetime2 TimestampUtc
        int UserId "no FK - history survives user changes"
        nvarchar UserEmail
        nvarchar Action
        nvarchar Target
        nvarchar Details
        nvarchar IpAddress
        bit Succeeded
    }
```

`AuditLogs` deliberately has no foreign key so audit history is never cascaded or blocked by
user changes. `FileRecords → Users` uses `DeleteBehavior.Restrict`.

## Key workflows

### Sign-in

```mermaid
sequenceDiagram
    actor U as User
    participant A as AccountController
    participant S as UserService
    participant DB as SQL Server
    U->>A: POST /Account/Login (antiforgery token, rate limited)
    A->>S: VerifyLoginAsync(email, password)
    S->>DB: load user by normalised e-mail
    alt unknown e-mail
        S->>S: hash dummy password (constant-ish timing)
    else locked out / inactive
        S-->>A: LockedOut / Inactive
    else wrong password
        S->>DB: FailedLoginCount++ (5 → 15 min lockout)
    else success
        S->>DB: reset counters, LastLoginAtUtc, rehash if needed
    end
    A->>DB: AuditLogs (LoginSucceeded / LoginFailed / LoginLockedOut)
    A-->>U: auth cookie (HttpOnly, SameSite=Strict, Secure outside dev)
```

Every request re-validates the cookie against the database (`CookieValidator`): if the
user was deactivated or their role changed (security stamp rotated) the session ends on
the next request.

### Upload

```mermaid
sequenceDiagram
    actor U as User
    participant F as FileController
    participant V as UploadValidator
    participant S3 as Amazon S3
    participant DB as SQL Server
    U->>F: POST /File/Upload (multipart, antiforgery)
    F->>V: name, size, extension allow-list
    alt rejected
        F->>DB: AuditLogs FileUploadRejected
    else accepted
        F->>S3: PutObject(random key, SSE header)
        F->>DB: FileRecords row (owner = current user)
        F->>DB: AuditLogs FileUploaded
        Note over F,S3: if the DB write fails the S3 object is deleted (no orphans)
    end
```

### Download / delete

1. The request carries the `FileRecords.Id` (GUID), never an S3 key.
2. `FileAccessPolicy.CanAccess` allows the owner or an Admin; anything else is audited as a
   failed `FileDownloaded` / `FileDeleted` and answered with **404** (no existence oracle).
3. Download redirects to a pre-signed GET URL (default 15 min) with a sanitised
   `Content-Disposition: attachment` file name. Delete removes the S3 object, then the row.

## Audit coverage

| Area | Actions recorded |
|---|---|
| Authentication | `LoginSucceeded`, `LoginFailed`, `LoginLockedOut`, `Logout`, `AccessDenied` |
| Files | `FileUploaded`, `FileUploadRejected`, `FileUploadFailed`, `FileDownloaded`, `FileDeleted` (failed attempts with `Succeeded = false`) |
| Administration | `UserCreated`, `UserRoleChanged`, `UserActivated`, `UserDeactivated`, `CloudTrailLogViewed`, `ReportExported` |

Each row stores timestamp, user id/e-mail, target, details, client IP and outcome. Admins can
filter by action, user and outcome, and export to CSV (formula-injection safe).

**Application audit log vs. CloudTrail:** the `AuditLogs` table answers *"which portal user did
what"*. CloudTrail (optional, separate bucket) answers *"which AWS principal called which S3
API"*. The portal lists and decompresses CloudTrail `.json.gz` files but does not parse or
correlate them.

## Configuration

All settings are bound to typed options and can be supplied via `appsettings.json`,
environment variables (`Section__Key`) or `dotnet user-secrets`.

| Key | Purpose | Default |
|---|---|---|
| `ConnectionStrings:DefaultConnection` | SQL Server connection | — (required) |
| `Database:ApplyMigrationsOnStartup` | run EF migrations at start-up | `false` (`true` in Development) |
| `Seed:AdminEmail` / `Seed:AdminName` / `Seed:AdminPassword` | first administrator, only if the Users table is empty | — |
| `Storage:BucketName` | S3 bucket for files | — (required) |
| `Storage:Region` | AWS region | `eu-central-1` |
| `Storage:ServiceUrl` / `Storage:PublicServiceUrl` / `Storage:ForcePathStyle` | S3-compatible endpoint (LocalStack, MinIO) | — |
| `Storage:ServerSideEncryption` / `Storage:KmsKeyId` | `aws:kms`, `AES256` or `None`; optional CMK | `aws:kms` |
| `Storage:PresignedUrlMinutes` | download link lifetime | `15` |
| `Storage:StorageQuotaMB` | informational budget on the Reports page | `1000` |
| `CloudTrail:BucketName` / `CloudTrail:AccountId` | optional CloudTrail viewer | — (feature hidden) |
| `Upload:MaxFileSizeMB` / `Upload:AllowedExtensions` | upload policy | `50` / pdf, docx, xlsx, txt, png, jpg, jpeg |
| `DataProtection:KeysPath` | persist cookie/antiforgery keys | in-memory/user profile |
| `UseHttpsRedirection` | disable behind a TLS-terminating proxy | `true` |

AWS credentials are **not** configuration: the SDK default credential chain is used (IAM role
on EC2/ECS/App Runner, `AWS_PROFILE`, or environment variables). `Storage:AccessKey` /
`Storage:SecretKey` exist only for S3-compatible local endpoints.
