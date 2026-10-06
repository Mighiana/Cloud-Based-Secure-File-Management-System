# Cloud-Based Secure File Management System

A secure file portal on **ASP.NET Core 8**, **SQL Server** and **Amazon S3** that treats every
upload as untrusted: files land in a private **quarantine** bucket, are re-hashed and
validated (file-signature checks, optional **ClamAV**), and only files that pass are copied to
the **approved** bucket and become downloadable. Sign-in uses hashed credentials with
**Admin / User roles** and per-user ownership, every security-relevant action goes to a
**hash-chained (tamper-evident) audit log**, and the AWS side is defined in **Terraform** with
offline security tests.

[![CI](https://github.com/Mighiana/Cloud-Based-Secure-File-Management-System/actions/workflows/ci.yml/badge.svg)](https://github.com/Mighiana/Cloud-Based-Secure-File-Management-System/actions/workflows/ci.yml)

![Admin security overview](docs/screenshots/09-admin-security-dashboard.png)

> **Project history.** This started as coursework for *Cloud Services and Security* at
> Óbuda University (Nov 2025, first pushed Dec 2025). That version did the S3 work (encrypted
> uploads, pre-signed downloads, CloudTrail log viewer) plus an S3-triggered Lambda + SNS
> upload-alert pipeline configured in the AWS console, but had no database, no working login
> and several simulated screens. In October 2026 it was refactored and extended: SQL Server,
> authentication, roles, audit log, the quarantine → validation → approval pipeline, ClamAV,
> the audit hash chain, CSP, Terraform, tests and the Docker demo were **added in 2026**, and
> the Lambda was **reconstructed as code**. See [Project history](#project-history).

---

## Contents

- [Problem and goals](#problem-and-goals) · [Features](#features) · [Screenshots](#screenshots)
- [Architecture](#architecture) · [File security pipeline](#file-security-pipeline) · [Security controls](#security-controls)
- [Run it locally](#run-it-locally-docker) · [Infrastructure as code](#infrastructure-as-code) · [Run against AWS](#run-against-aws)
- [Tests and CI](#tests-and-ci) · [Technical decisions](#technical-decisions) · [Challenges](#challenges)
- [Status and limitations](#status-and-limitations) · [Project history](#project-history)
- [Threat model](docs/threat-model.md) · [Architecture details](docs/architecture.md)

## Problem and goals

Shared document storage often means one bucket or drive, no per-user access control, no
check of what was uploaded and no record of who did what. This portal is a self-hosted front
end over S3 with these goals:

- **Nothing uploaded is trusted or served until it is validated.** Unvalidated, rejected and
  quarantined files cannot be downloaded, enforced on the server and by bucket separation.
- **Least privilege** for users (own files only, admin role for management) and for cloud
  identities (separate IAM roles for web app, validator and Lambda).
- **Accountability:** an application audit trail of who did what, which can be checked for
  edits or deletions, alongside AWS CloudTrail.
- **Reproducible and checkable** without an AWS account: Docker demo, offline Terraform tests.

**Intended users:** regular users who upload and retrieve their own documents, and
administrators who manage accounts, review security events and re-scan quarantined files.

## Features

| Area | What it does |
|---|---|
| **Authentication** | E-mail + password, ASP.NET Core `PasswordHasher` (PBKDF2), 5 failures → 15-min lockout, 10/min per-IP login rate limit, security-stamp session revocation |
| **Authorization** | `Admin` / `User` roles, authenticated-by-default fallback policy, `[Authorize(Roles = "Admin")]` admin area, owner-or-admin check on every file action (foreign files → 404, audited) |
| **Upload checks** | Size limit, narrow extension allow-list, magic-byte signature check (an `.exe` renamed `.pdf` is refused), SHA-256, duplicate and known-quarantined-hash rejection, content type derived server-side |
| **Validation pipeline** | `Pending → Validating → Approved / Rejected / Quarantined`; background worker re-hashes the stored object, re-checks the signature, optionally scans with ClamAV; fail-closed retries; admin re-scan |
| **Two-bucket storage** | Private quarantine and approved S3 buckets, random object keys, SSE-S3 by default (SSE-KMS optional); objects are promoted only after approval |
| **Download gate** | Pre-signed URL (15 min) only for `Approved` files in the approved bucket; every other attempt is blocked and audited as `DownloadBlockedSecurityState` |
| **File details** | State, reason, engines, attempts, SHA-256, storage area and the file's audit history (object key shown to admins only) |
| **Audit log** | Logins, lockouts, access denials, uploads, validation results, downloads, blocked downloads, deletes, admin changes; filterable, paginated, CSV export |
| **Audit integrity** | Each entry hash-chained to the previous one (SHA-256); admin **Audit Integrity** page re-verifies the chain |
| **Admin dashboard** | Files by security state, failed sign-ins, blocked downloads, upload rejections, scan failures, recent security events, 7-day activity, all from the database |
| **User management** | Create users, promote/demote, activate/deactivate (cannot lock yourself out) |
| **CloudTrail viewer** | Lists and decompresses `.json.gz` logs from a configured CloudTrail bucket (optional) |
| **Reports** | CSV exports: file inventory, audit trail, CloudTrail index (formula-injection safe) |
| **Upload-scan Lambda** | S3-triggered Python function on the quarantine bucket: hygiene checks, `scan-status` tags, SNS alerts, duplicate-event suppression, DLQ ([details](#2025-upload-alerts-aws-lambda--sns)) |
| **Infrastructure** | Terraform root module with `terraform test`, TFLint, Checkov; Docker Compose with SQL Server, LocalStack (S3, SNS, SQS, Lambda) and ClamAV |

## Screenshots

All screenshots are from the current code running in the Docker demo below (demo accounts,
LocalStack instead of AWS, real ClamAV container). The "malware" is the harmless
[EICAR test file](https://www.eicar.org/download-anti-malware-testfile/); CloudTrail entries
are **synthetic fixtures**.

| | |
|---|---|
| **Upload: checks → SHA-256 → quarantine → scan** ![Upload](docs/screenshots/03-upload-page.png) | **Renamed executable refused at upload** ![Signature mismatch](docs/screenshots/03a-upload-rejected-signature.png) |
| **ClamAV down: file stays Pending (fail-closed)** ![Pending](docs/screenshots/04-my-files-states.png) | **Retry history while the scanner is unavailable** ![Scan retry](docs/screenshots/05-file-details-scan-retry.png) |
| **After validation: Approved vs Quarantined** ![Files](docs/screenshots/04b-my-files-after-retry.png) | **Download of a quarantined file blocked** ![Blocked](docs/screenshots/06-download-blocked-quarantined.png) |
| **Approved file: SHA-256 and audit history** ![Approved details](docs/screenshots/07-file-details-approved.png) | **Re-upload of a quarantined file refused by hash** ![Known-bad hash](docs/screenshots/03c-upload-rejected-known-bad-hash.png) |
| **Audit chain verification** ![Integrity](docs/screenshots/15-audit-chain-integrity.png) | **Audit log** ![Audit log](docs/screenshots/13-audit-log.png) |
| **Audit - failures only** ![Audit failures](docs/screenshots/14-audit-failures.png) | **Admin view of a quarantined file (re-scan)** ![Admin details](docs/screenshots/12-admin-file-details-quarantined.png) |
| **Sign-in** ![Login](docs/screenshots/01-login.png) | **User blocked from admin area** ![Access denied](docs/screenshots/08-access-denied.png) |
| **User dashboard** ![User dashboard](docs/screenshots/02-user-dashboard.png) | **Users & roles** ![Users](docs/screenshots/10-admin-users.png) |
| **All files (admin)** ![All files](docs/screenshots/11-admin-all-files.png) | **Duplicate upload refused** ![Duplicate](docs/screenshots/03b-upload-rejected-duplicate.png) |
| **CloudTrail viewer** ![CloudTrail](docs/screenshots/16-cloudtrail-logs.png) | **Reports** ![Reports](docs/screenshots/17-reports.png) |

Screenshots of the original 2025 coursework UI are kept in
[`docs/screenshots/original-2025`](docs/screenshots/original-2025).

### 2025 upload alerts (AWS Lambda + SNS)

In the original coursework deployment (AWS `eu-north-1`, Nov 2025), uploads to the files bucket
triggered a **Lambda function** that ran a basic post-upload check - the coursework report
describes it as a *simulated* scan, not a malware engine - and published the result to an
**SNS topic** (`FileUploadAlerts`) that e-mailed subscribers "FILE SCAN SUCCESSFUL" or
"FILE SCAN FAILED" with the file name, bucket, size, type and timestamp:

![SNS e-mails from the 2025 Lambda scan](docs/screenshots/original-2025/sns-scan-alerts.png)

That function was written and configured in the AWS console and its original source was never
committed. **[`lambda/upload-scan`](lambda/upload-scan) is a 2026 reconstruction of that function as code**, deployed by
[`deploy/aws`](deploy/aws) on the quarantine bucket:

```mermaid
flowchart LR
    APP[Portal upload] --> S3[(Quarantine bucket)]
    S3 -->|s3:ObjectCreated:*| L[Lambda<br/>upload-scan]
    L -->|read first 8 KB| S3
    L -->|tag scan-status| S3
    L -->|Scan Complete / Scan Failed| SNS[[SNS FileUploadAlerts]]
    SNS -->|e-mail| SUB([Subscribers])
```

- Checks each new object: not empty, within the size limit, allowed extension, and that the
  first bytes match the file type - so an executable renamed to `.pdf` is flagged.
- Tags the object `scan-status=clean|rejected|error`, `scan-reason` and `scan-etag`, and
  publishes the same style of e-mail as 2025 to SNS. A redelivered S3 event for an object
  version that was already scanned is skipped (no duplicate alert); failures are retried and
  then sent to an SQS dead-letter queue.
- Verified with 29 pytest/moto tests and in the Docker demo, where LocalStack runs the same
  handler on the quarantine bucket. It has **not been deployed to a real AWS account** from
  this repo.

These are file-hygiene checks, **not malware scanning**. The Lambda is an independent alerting
path; approval is decided only by the portal's validation worker. See
[`lambda/upload-scan/README.md`](lambda/upload-scan/README.md).

## Architecture

![Architecture: user, application, quarantine and approved buckets, validation worker, ClamAV, SQL Server, Lambda, Terraform](docs/architecture.png)

```mermaid
flowchart LR
    U([User]) -->|HTTPS| APP[ASP.NET Core 8 MVC<br/>auth · roles · CSP · upload checks]
    APP -->|PutObject| Q[(S3 quarantine)]
    APP <-->|users, files, audit chain| SQL[(SQL Server)]
    W[Validation worker<br/>basic + ClamAV] -->|read + re-hash| Q
    W -->|copy if clean| A[(S3 approved)]
    W -->|state + audit| SQL
    APP -->|pre-signed GET, Approved only| A
    Q -.->|S3 event| L[upload-scan Lambda] -.-> SNS[[SNS alerts]]
```

Component, state, sequence and data-model diagrams, the audit-event list, IAM design and
the configuration reference are in **[docs/architecture.md](docs/architecture.md)**. The threat
model (threat → control → gap) is in **[docs/threat-model.md](docs/threat-model.md)**.

| | |
|---|---|
| Backend | C#, ASP.NET Core 8 MVC, EF Core 8, hosted background worker |
| Database | SQL Server (code-first migrations) |
| Storage | Amazon S3 via AWS SDK for .NET; quarantine + approved buckets; SSE-S3 / SSE-KMS |
| Scanning | File-signature checks, ClamAV 1.4 (clamd `INSTREAM`) - optional |
| Serverless | AWS Lambda (Python 3.12, boto3) + SNS + SQS DLQ |
| Infrastructure | Terraform 1.9 (`terraform test` with mocked provider), TFLint, Checkov, ShellCheck |
| Frontend | Razor views, Bootstrap 5, Font Awesome, Chart.js - all served locally under a strict CSP |
| Tests | xUnit + `WebApplicationFactory`, EF Core InMemory; pytest + moto |
| Local demo | Docker Compose: SQL Server 2022, LocalStack 3.8 (S3, SNS, SQS, Lambda), ClamAV, app |
| CI | GitHub Actions: build (warnings as errors), tests against a real clamd, migration drift check, Lambda tests, Terraform fmt/validate/test, TFLint, Checkov, ShellCheck |

```
SecureFileUploadPortal/
  Controllers/   Account, Home, File, Admin
  Data/          Entities, AppDbContext, DbInitializer, Migrations/
  Security/      cookie validation, claims, file access policy, security headers + CSP
  Services/      UserService, AuditService, AuditChain, S3FileStorageService, FileSignatures, UploadValidator, ...
  Validation/    IFileSecurityScanner, BasicFileValidationScanner, ClamAvSecurityScanner, worker + processor
  Views/, wwwroot/   Razor UI, local JS/CSS libraries
SecureFileUploadPortal.Tests/   unit, pipeline and HTTP-level integration tests
lambda/upload-scan/             upload-scan function (Python) + pytest suite
deploy/aws/                     Terraform: buckets, IAM roles, Lambda, SNS, DLQ + tests
deploy/localstack/init-aws.sh   local buckets, SNS/SQS, Lambda, synthetic CloudTrail fixtures
scripts/bootstrap-tools.sh      pinned, checksum-verified tool installer (make bootstrap)
```

## File security pipeline

```
upload ─▶ checks (size · extension · magic bytes · SHA-256 · known-bad hash)
       ─▶ S3 quarantine  [Pending]
       ─▶ worker: re-hash + signature + ClamAV  [Validating]
       ─▶ clean ─▶ copy to S3 approved  [Approved]  ─▶ download enabled
          mismatch ─▶ [Rejected]   malware / repeated scanner failure ─▶ [Quarantined]
```

- **Fail-closed.** If ClamAV is unreachable or times out the scan result is `Error`: the file
  goes back to `Pending` and is retried (`Validation:MaxAttempts`, default 3) and is then
  quarantined. It is never approved because a scanner was down.
- **Defence in depth for downloads.** The server checks `Status == Approved` and
  `StorageArea == Approved` before generating a URL, and URLs can only be signed for the
  approved bucket, which only the worker writes to.
- **SHA-256** is integrity and duplicate-detection metadata (does the stored object still
  match what was uploaded?), not a signature or proof of authorship.
- **ClamAV** is signature-based malware detection. Without it (`CLAMAV_ENABLED=false`) only the
  basic checks run; the docs and UI then report the basic engine only.

## Security controls

Implemented and covered by tests unless noted:

- **Passwords** hashed with ASP.NET Core Identity's `PasswordHasher` (PBKDF2), upgraded
  automatically if parameters change; minimum length 10.
- **Brute force:** lockout after 5 failures (15 min), 10 requests/min per IP on
  `POST /Account/Login`, dummy hash for unknown e-mails.
- **Session cookie:** `HttpOnly`, `SameSite=Strict`, `Secure` outside Development, 30-min
  sliding expiry, re-validated against the database on each request (deactivation or role
  change ends the session).
- **Authorization:** authenticated-by-default fallback policy, admin-only controller, ownership
  check on every file action; denials audited.
- **CSRF:** global antiforgery validation.
- **Headers:** CSP `default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none';
  frame-ancestors 'none'; ...` (no inline script or style, no CDN), `X-Content-Type-Options`,
  `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`,
  `Cross-Origin-Opener-Policy`, HSTS outside Development. A test renders every page and fails
  on inline scripts or styles.
- **Uploads / validation / downloads:** see [File security pipeline](#file-security-pipeline).
- **Audit:** no passwords, tokens, credentials, pre-signed URLs or file contents are logged;
  entries are hash-chained (tamper-evident, not tamper-proof).
- **Storage (Terraform and local demo):** Public Access Block, ACLs disabled
  (`BucketOwnerEnforced`), TLS-only bucket policies, versioning, default encryption, access
  logging (Terraform), lifecycle rules.
- **Secrets:** nothing committed; AWS SDK default credential chain; DB connection and seed
  admin from environment variables or `dotnet user-secrets`.

## Run it locally (Docker)

Needs Docker with Compose (about 4 GB RAM free; the ClamAV container downloads its signature
database on first start, which takes a few minutes). No AWS account required.

```bash
git clone https://github.com/Mighiana/Cloud-Based-Secure-File-Management-System.git
cd Cloud-Based-Secure-File-Management-System
cp .env.example .env          # then set MSSQL_SA_PASSWORD and SEED_ADMIN_PASSWORD
docker compose up -d --build
```

Open <http://localhost:8080> and sign in with `SEED_ADMIN_EMAIL` / `SEED_ADMIN_PASSWORD`.
A demo path:

1. **Users & roles** → create a normal user; sign in as them in a private window.
2. Upload a PDF → it shows **Pending**, then **Approved** a few seconds later; open it to see
   the SHA-256 and audit history, then download.
3. Rename any `.exe` to `.pdf` and upload it → refused (signature mismatch).
4. Save the [EICAR test string](https://www.eicar.org/download-anti-malware-testfile/) as
   `eicar.txt` and upload it → **Quarantined** by ClamAV; download is blocked and audited.
5. `docker compose stop clamav`, upload another file → it stays **Pending** with retry
   attempts; `docker compose start clamav` → it is approved on the next attempt.
6. As admin: **Admin Dashboard** (security metrics), **Audit Log**, **Audit Integrity**.

| Service | Purpose |
|---|---|
| `sqlserver` | SQL Server 2022 Developer; schema created by EF migrations on app start |
| `aws` | LocalStack community: `deploy/localstack/init-aws.sh` creates private, versioned, encrypted `secure-files-quarantine` and `secure-files-approved` buckets, the `FileUploadAlerts` SNS topic with an SQS inbox, the upload-scan Lambda on the quarantine bucket (`UPLOAD_SCAN_LAMBDA=false` to skip; needs the Docker socket) and a `demo-cloudtrail` bucket with synthetic logs |
| `clamav` | ClamAV 1.4 daemon (`CLAMAV_ENABLED=false` to run basic validation only) |
| `app` | this application on port 8080, non-root, Data Protection keys on a volume |

`docker compose down -v` removes everything including data.

### Without Docker (`dotnet run`)

Needs the .NET 8 SDK, SQL Server and S3 or an S3-compatible endpoint (e.g. LocalStack on
`localhost:4566`, which `appsettings.Development.json` points to).

```bash
cd SecureFileUploadPortal
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Server=localhost;Database=SecureFilePortal;User Id=sa;Password=...;TrustServerCertificate=True"
dotnet user-secrets set "Seed:AdminEmail" "admin@example.com"
dotnet user-secrets set "Seed:AdminPassword" "<at least 10 characters>"
dotnet user-secrets set "Storage:QuarantineBucketName" "<quarantine bucket>"
dotnet user-secrets set "Storage:ApprovedBucketName" "<approved bucket>"
dotnet run
```

## Infrastructure as code

[`deploy/aws`](deploy/aws) is a Terraform root module for the AWS side: the quarantine,
approved and access-log buckets (private, versioned, encrypted, TLS-only, lifecycle rules),
separate least-privilege IAM roles for the web app and the validator, and the upload-scan
Lambda with its SNS topic, SQS dead-letter queue and log group. SSE-S3 is the default to avoid
KMS cost; set `kms_key_arn` for SSE-KMS. Details: [docs/architecture.md](docs/architecture.md#infrastructure-as-code-deployaws).

All checks run offline, without AWS credentials:

```bash
make bootstrap   # pinned Terraform, TFLint, ShellCheck (SHA-256 verified) + Checkov/pytest venvs in .tools/
make init        # terraform init -backend=false, tflint --init, dotnet restore
make check       # fmt, validate, terraform test, TFLint, Checkov, ShellCheck, .NET tests, Lambda tests
```

`terraform test` uses a mocked AWS provider and asserts, among others, that every bucket
blocks public access and denies non-TLS requests, that no IAM statement grants `*` actions or
`*` resources, and that the web role cannot write to the approved bucket. Checkov passes with
12 documented, inline skips (e.g. cross-region replication and SSE-KMS-by-default are cost
decisions). This Terraform has been validated and tested offline only; **it has not been
applied to a real AWS account.**

## Run against AWS

1. `cd deploy/aws && cp terraform.tfvars.example terraform.tfvars`, set `name_prefix`, region
   and alert e-mails, then `terraform init && terraform apply`. Confirm the SNS e-mail
   subscription.
2. Run the app with the `web_role_arn` output role (trusted by ECS tasks by default; change
   `app_trusted_services` for EC2 or App Runner) and configure:

   ```bash
   ConnectionStrings__DefaultConnection="Server=...;Database=SecureFilePortal;..."
   Storage__QuarantineBucketName=<quarantine_bucket output>
   Storage__ApprovedBucketName=<approved_bucket output>
   Storage__Region=eu-central-1
   Validation__ClamAv__Enabled=true  Validation__ClamAv__Host=<clamd host>   # optional
   CloudTrail__BucketName=...  CloudTrail__AccountId=...                      # optional
   Seed__AdminEmail=... Seed__AdminPassword=...                               # first run only
   DataProtection__KeysPath=/var/keys                                         # persistent storage
   ```
3. Apply migrations (`dotnet ef database update` or `Database__ApplyMigrationsOnStartup=true`).
4. Terminate TLS in front of the app; set `UseHttpsRedirection=false` only behind a TLS proxy.

Credentials come from the AWS SDK default chain; do not put access keys in config.
**There is currently no public live deployment.**

## Tests and CI

```bash
make check                       # everything below, offline
dotnet test SecureFileUploadPortal.sln
```

- **99 .NET tests.** Unit tests: upload validator, file signatures (PDF/PNG/JPEG/ZIP/text,
  disguised executables, binary text), ownership policy, CSV escaping, password hashing,
  lockout, security stamps, audit-chain verification (edited, deleted and legacy entries),
  clamd protocol parsing. Pipeline tests: approval and promotion, hash mismatch → rejected,
  malware verdict → quarantined, scanner outage → retries → quarantined, unreadable object
  fails closed, stale `Validating` records re-queued. Integration tests (`WebApplicationFactory`,
  in-memory DB, fake two-bucket S3) over HTTP: anonymous redirects, antiforgery, login audit,
  admin-only pages, upload → `Pending`, signature mismatch, duplicates, the download gate for
  every non-approved state, ownership, CSP on every page, login rate limiting.
- **EICAR against a real ClamAV** runs when `CLAMAV_HOST` is set (CI starts a clamd service
  container).
- **29 Lambda tests** (pytest + moto): checks, tagging, SNS, URL-encoded keys, deleted objects,
  duplicate events, new versions, error tagging and retries.
- **Terraform:** 6 `terraform test` runs, TFLint, Checkov; **ShellCheck** on the shell scripts.

## Technical decisions

- **Two buckets instead of a prefix.** IAM and bucket policies can then separate "can write
  uploads" from "can serve files", and the download gate is enforced twice (database state and
  bucket).
- **Validation in the app's worker, not in Lambda.** It keeps the state machine, retries and
  audit in one place next to the database and works identically in Docker; the Lambda stays a
  simple, independent alerting path.
- **Scanner interface.** `IFileSecurityScanner` makes the basic checks mandatory and ClamAV
  optional, and lets a commercial scanner be added without touching the pipeline.
- **Fail closed** rather than fail open when a scanner is down, accepting that a long outage
  quarantines legitimate files (admins can re-scan).
- **Hash-chained audit log in SQL** rather than a separate ledger service: cheap, verifiable,
  honest about its limits (tamper-evident).
- **Metadata in SQL, bytes in S3; random keys** so no user input ever becomes an object key.
- **Cookie auth + a small `Users` table** instead of full ASP.NET Core Identity, reusing
  Identity's `PasswordHasher`; a security stamp gives immediate revocation.
- **Strict CSP with self-hosted assets** instead of allowing CDNs or `unsafe-inline`.
- **SSE-S3 by default** to keep the demo free; SSE-KMS is a variable.
- **Removed simulated features** (Macie scan, Glacier backup, browser-only MFA, hard-coded
  charts) instead of keeping UI that pretended to work.

## Challenges

- **Making the original code actually secure.** It referenced a cookie scheme that was never
  registered and had no `[Authorize]`, so every page - including delete - was public.
- **A state machine that survives failures.** Claiming work with optimistic concurrency,
  re-queuing records stuck in `Validating` after a crash, retry back-off, and never letting an
  error path end in `Approved`.
- **Local AWS that behaves like AWS.** Pre-signed URLs must be signed for the host the browser
  sees, LocalStack's Lambda needs the Docker socket and a shared network, and ClamAV needs
  minutes to load signatures - all handled by health checks in Compose.
- **CSP without breaking the UI.** CDN assets were moved local, inline scripts moved to files,
  and even ASP.NET's validation-summary helper (which emits an inline `style`) had to be
  rendered only when there are errors.
- **Keeping S3 and the database consistent.** Uploads that reach S3 but fail to save metadata
  are deleted again; promotion copies, then deletes from quarantine, then updates state.

## Status and limitations

**Working:** everything in [Features](#features), verified with the test suites and end to end
in the Docker demo (upload → quarantine → ClamAV → approved bucket → download; EICAR
quarantined; scanner outage → retries; Lambda tags and SNS alert in LocalStack).

**Not implemented / limits:**

- multi-factor authentication, self-service registration, password reset
- detection beyond signatures: macros, PDF JavaScript, polyglots and zero-days are not caught;
  ClamAV is optional
- per-user quotas and upload rate limits
- external anchoring of the audit chain (a database admin can rewrite it)
- parsing or correlating CloudTrail events (the viewer shows raw JSON)
- file sharing between users, folders
- the Terraform and Lambda have **not been deployed to a real AWS account** from this repo
- Data Protection keys are stored unencrypted on the configured path

**Optional production hardening** (not used here, some paid): GuardDuty Malware Protection for
S3, Macie, WAF, Security Hub, KMS-encrypted Data Protection keys, S3 Object Lock for audit
exports, GitHub OIDC deployment. See [docs/threat-model.md](docs/threat-model.md).

## Project history

| When | What |
|---|---|
| Nov 2025 | Coursework for *Cloud Services and Security*, Óbuda University (report and presentation). AWS-side setup was configured in the console: S3 buckets, KMS key, CloudTrail trail, and an S3-triggered Lambda (simulated scan) publishing to an SNS e-mail topic. The Lambda code was never committed. |
| Dec 2025 | Code pushed: S3 upload/list/download/delete with SSE-KMS and pre-signed URLs, CloudTrail log viewer, CSV exports, admin UI. Several screens were placeholders. |
| Oct 2026 | Refactor: SQL Server + EF Core, password hashing, roles, ownership checks, persistent audit log, user management, removal of simulated features, configuration/secrets cleanup, tests, CI and Docker demo. Upload-scan Lambda reconstructed as Python + Terraform. |
| Oct 2026 | Security extension: quarantine/approved buckets, `Pending → Validating → Approved/Rejected/Quarantined` pipeline, file-signature checks, SHA-256, ClamAV scanner, fail-closed worker, download gate, hash-chained audit log, CSP, security dashboard, Terraform root module with IAM roles and offline tests, Makefile, threat model. |
