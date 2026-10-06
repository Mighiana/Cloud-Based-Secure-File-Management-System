# Threat model

Scope: the portal as implemented in this repository (ASP.NET Core app, validation worker,
SQL Server, two S3 buckets, the upload-scan Lambda and the Terraform in `deploy/aws`).
"Gap" lists what the control does **not** cover. Nothing here has been penetration-tested,
and the Terraform has only been applied to LocalStack and a mocked provider, not to a real
AWS account.

## Assets and trust boundaries

| Asset | Where |
|---|---|
| File contents | S3 quarantine bucket → approved bucket (SSE-S3 by default, SSE-KMS optional) |
| Accounts, file metadata, security state | SQL Server (`Users`, `FileRecords`) |
| Audit trail | SQL Server (`AuditLogs`, hash-chained) |
| Session / antiforgery keys | ASP.NET Core Data Protection key ring |

Boundaries: browser ↔ app (untrusted input), app ↔ S3/SQL (trusted service identity),
clamd (separate container), Lambda (separate IAM role, triggered by S3 events).

## Threats, controls and gaps

| Threat | Control in this repo | Gap |
|---|---|---|
| Password guessing / credential stuffing | PBKDF2 hashing (`PasswordHasher`), 5 failures → 15-min lockout, 10 req/min per-IP limit on `POST /Account/Login`, dummy hash for unknown e-mails | No MFA; lockout can be used to lock a known account out for 15 min |
| Session theft / stale privileges | `HttpOnly`, `SameSite=Strict`, `Secure` cookie, 30-min sliding expiry; security stamp re-checked every request, so role change or deactivation ends sessions | No device/IP binding; Data Protection keys stored unencrypted on disk |
| CSRF | Global antiforgery validation on unsafe methods | — |
| XSS / script injection | Razor output encoding; CSP `script-src 'self'` with no inline script or CDN; `object-src 'none'` | CSP does not protect against a compromised local asset |
| Clickjacking | `frame-ancestors 'none'`, `X-Frame-Options: DENY` | — |
| Accessing another user's file (IDOR) | Requests use database GUIDs, never S3 keys; `FileAccessPolicy` owner-or-admin check; foreign files return 404 and are audited | Admins can read every file by design |
| Privilege escalation | Authenticated-by-default fallback policy; `[Authorize(Roles = "Admin")]` on the admin controller; admins cannot demote/deactivate themselves | Only two roles; no per-file sharing model |
| Executable disguised as a document | Narrow extension allow-list plus magic-byte checks at upload **and** again on the stored object by the worker (`FileSignatures`) | Polyglot files, Office macros and PDF JavaScript are not detected; a valid PDF/DOCX can still be malicious |
| Known malware | Optional ClamAV (`clamd INSTREAM`); tested with the harmless EICAR test string only | Signature-based only; with `ClamAv:Enabled=false` only the basic checks run |
| Scanner outage used to slip files through | Fail-closed: scanner errors are retried (`MaxAttempts`, default 3) and then the file is **quarantined**, never approved | A long outage quarantines legitimate files; an admin must rescan them |
| Downloading unvalidated content | Download gate: URL only when `Status = Approved` and `StorageArea = Approved`; pre-signed URLs are only ever generated for the approved bucket; blocked attempts audited as `DownloadBlockedSecurityState` | — |
| Object swapped in quarantine before validation | Worker recomputes SHA-256 of the stored object and rejects on mismatch with the upload-time hash | Objects are not re-hashed after promotion to the approved bucket |
| Re-upload of a file already quarantined | Upload rejected if its SHA-256 matches a quarantined file; exact duplicates per user rejected | Changing one byte produces a new hash, so this is not a malware control |
| Public or misconfigured buckets | Terraform and the LocalStack init script: Public Access Block, `BucketOwnerEnforced` (ACLs off), TLS-only bucket policy (TLS ≥ 1.2), versioning, default encryption, access logging | Not verified against a real AWS account from this repo |
| Over-privileged cloud identities | Scoped policies on two roles: web app (also runs the validation worker) and Lambda (quarantine bucket, its SNS topic, DLQ and logs only; no access to approved files); `terraform test` asserts no `*`/`service:*` actions and no `Resource: "*"` | The worker shares the web role, so a compromised web process could write to the approved bucket directly; a separate worker process and role is not implemented |
| Pre-signed URL leakage | 15-minute default lifetime; URLs are never written to the audit log | Anyone holding a leaked URL can use it until it expires |
| Audit log tampering | Each entry stores `PreviousHash` and `EntryHash` (SHA-256 over a canonical JSON form); admin **Integrity** page re-verifies the chain and reports edited or missing entries | Tamper-**evident**, not tamper-proof: someone with write access to the database can rewrite and re-hash the whole chain; no external anchoring |
| Repudiation | Audit rows record user, IP, target, outcome and timestamp for logins, uploads, validation, downloads, deletes and admin actions | IP is taken from the connection; behind a proxy, forwarded headers must be configured |
| Resource exhaustion via uploads | Kestrel and validator size limit (default 50 MB); worker batch size; Lambda reserved concurrency and reads at most 8 KB | No per-user quota enforcement or upload rate limit |
| Duplicate S3 events | Lambda records the object ETag (`scan-etag`) and skips already-scanned versions; failed events go to an SQS DLQ | — |
| Secrets in the repository | `.env` / production settings git-ignored; AWS SDK default credential chain; no keys in config | Local demo uses LocalStack's dummy `test` credentials |
| Tooling supply chain | `make bootstrap` installs pinned Terraform / TFLint / ShellCheck versions with SHA-256 verification; front-end libraries served locally | NuGet and pip packages are version-pinned but not hash-locked |

## Out of scope / optional production hardening

Not implemented and not required for the demo: MFA, WAF, GuardDuty, Macie, Security Hub,
Inspector, a managed malware-scanning service, KMS-protected Data Protection keys, external
anchoring of the audit chain (e.g. S3 Object Lock), and GitHub OIDC deployment.
