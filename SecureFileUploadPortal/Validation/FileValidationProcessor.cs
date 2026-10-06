using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureFileUploadPortal.Data;
using SecureFileUploadPortal.Options;
using SecureFileUploadPortal.Services;

namespace SecureFileUploadPortal.Validation;

/// <summary>
/// Moves files through Pending → Validating → Approved / Rejected / Quarantined.
/// Only a unanimous Clean from every scanner approves a file; scanner errors are retried and then quarantined.
/// </summary>
public sealed class FileValidationProcessor(
    AppDbContext db,
    IFileStorageService storage,
    IEnumerable<IFileSecurityScanner> scanners,
    AuditService audit,
    IOptions<ValidationOptions> options,
    TimeProvider clock,
    ILogger<FileValidationProcessor> logger)
{
    public const string Actor = "system:validator";
    private readonly ValidationOptions _options = options.Value;

    /// <summary>Processes due Pending files and returns how many were handled.</summary>
    public async Task<int> ProcessPendingAsync(CancellationToken ct)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        await RequeueStaleAsync(now, ct);

        var due = await db.Files.AsNoTracking()
            .Where(f => f.Status == FileSecurityStatus.Pending && (f.NextAttemptAtUtc == null || f.NextAttemptAtUtc <= now))
            .OrderBy(f => f.UploadedAtUtc)
            .Select(f => f.Id)
            .Take(_options.BatchSize)
            .ToListAsync(ct);

        foreach (var id in due) await ProcessAsync(id, ct);
        return due.Count;
    }

    public async Task ProcessAsync(Guid id, CancellationToken ct)
    {
        var file = await ClaimAsync(id, ct);
        if (file is null) return;

        var outcome = await ScanAsync(file, ct);

        switch (outcome.Verdict)
        {
            case ScanVerdict.Clean: await ApproveAsync(file, outcome, ct); break;
            case ScanVerdict.Rejected: await RejectAsync(file, outcome, ct); break;
            case ScanVerdict.Infected: await QuarantineAsync(file, outcome.Engine, $"malware signature detected ({outcome.Detail})", ct); break;
            default: await HandleScanErrorAsync(file, outcome, ct); break;
        }
    }

    /// <summary>Atomically flips Pending → Validating; returns null if another worker got there first.</summary>
    private async Task<FileRecord?> ClaimAsync(Guid id, CancellationToken ct)
    {
        var file = await db.Files.SingleOrDefaultAsync(f => f.Id == id, ct);
        if (file is not { Status: FileSecurityStatus.Pending }) return null;

        file.Status = FileSecurityStatus.Validating;
        file.ValidationStartedAtUtc = clock.GetUtcNow().UtcDateTime;
        file.ValidationAttempts++;
        file.ConcurrencyStamp = Guid.NewGuid();
        if (!await TrySaveAsync(file, ct)) return null;

        await LogAsync(AuditActions.FileValidationStarted, true, file, $"attempt {file.ValidationAttempts}/{_options.MaxAttempts}; sha256={file.Sha256}", ct);
        return file;
    }

    private async Task<ScanResult> ScanAsync(FileRecord file, CancellationToken ct)
    {
        var tempPath = Path.Combine(Path.GetTempPath(), $"scan-{Guid.NewGuid():N}");
        try
        {
            await using (var target = new FileStream(tempPath, FileMode.CreateNew, FileAccess.Write))
                await storage.ReadQuarantinedAsync(file.StorageKey, target, ct);

            var context = new FileScanContext(file, () => new FileStream(tempPath, FileMode.Open, FileAccess.Read, FileShare.Read));
            var engines = new List<string>();
            foreach (var scanner in scanners)
            {
                var result = await scanner.ScanAsync(context, ct);
                engines.Add(result.Engine);
                if (result.Verdict != ScanVerdict.Clean) return result;
            }
            return ScanResult.Clean(string.Join(" + ", engines), "all checks passed");
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested)
        {
            logger.LogWarning(ex, "Could not read file {FileId} for validation", file.Id);
            return ScanResult.Error("storage", $"could not read the quarantined object ({ex.GetType().Name})");
        }
        finally
        {
            File.Delete(tempPath);
        }
    }

    private async Task ApproveAsync(FileRecord file, ScanResult outcome, CancellationToken ct)
    {
        try
        {
            await storage.CopyToApprovedAsync(file.StorageKey, file.ContentType, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogWarning(ex, "Promoting file {FileId} failed", file.Id);
            await HandleScanErrorAsync(file, ScanResult.Error("storage", $"copy to approved bucket failed ({ex.GetType().Name})"), ct);
            return;
        }

        Finish(file, FileSecurityStatus.Approved, outcome.Engine, outcome.Detail);
        file.StorageArea = StorageArea.Approved;
        if (!await TrySaveAsync(file, ct))
        {
            // The record changed underneath us (e.g. the owner deleted it): don't leave an orphaned approved copy.
            await TryDeleteAsync(StorageArea.Approved, file.StorageKey);
            return;
        }
        await TryDeleteAsync(StorageArea.Quarantine, file.StorageKey);
        await LogAsync(AuditActions.FileValidationApproved, true, file, $"{outcome.Engine}: {outcome.Detail}", ct);
    }

    private async Task RejectAsync(FileRecord file, ScanResult outcome, CancellationToken ct)
    {
        Finish(file, FileSecurityStatus.Rejected, outcome.Engine, outcome.Detail);
        if (!await TrySaveAsync(file, ct)) return;
        await TryDeleteAsync(StorageArea.Quarantine, file.StorageKey);
        await LogAsync(AuditActions.FileValidationRejected, false, file, $"{outcome.Engine}: {outcome.Detail}", ct);
    }

    private async Task QuarantineAsync(FileRecord file, string engine, string reason, CancellationToken ct)
    {
        Finish(file, FileSecurityStatus.Quarantined, engine, reason);
        if (!await TrySaveAsync(file, ct)) return;
        await LogAsync(AuditActions.FileQuarantined, false, file, $"{engine}: {reason}", ct);
    }

    private async Task HandleScanErrorAsync(FileRecord file, ScanResult outcome, CancellationToken ct)
    {
        await LogAsync(AuditActions.FileScanFailed, false, file,
            $"{outcome.Engine}: {outcome.Detail}; attempt {file.ValidationAttempts}/{_options.MaxAttempts}", ct);

        if (file.ValidationAttempts >= _options.MaxAttempts)
        {
            await QuarantineAsync(file, outcome.Engine, $"not approved: scan failed {file.ValidationAttempts} times ({outcome.Detail})", ct);
            return;
        }

        file.Status = FileSecurityStatus.Pending;
        file.StatusReason = $"scan failed, retrying ({outcome.Detail})";
        file.NextAttemptAtUtc = clock.GetUtcNow().UtcDateTime.AddSeconds(_options.RetryDelaySeconds * file.ValidationAttempts);
        file.ConcurrencyStamp = Guid.NewGuid();
        await TrySaveAsync(file, ct);
    }

    private void Finish(FileRecord file, FileSecurityStatus status, string engine, string reason)
    {
        file.Status = status;
        file.StatusReason = Truncate(reason, 500);
        file.ScanEngine = Truncate(engine, 200);
        file.ValidatedAtUtc = clock.GetUtcNow().UtcDateTime;
        file.NextAttemptAtUtc = null;
        file.ConcurrencyStamp = Guid.NewGuid();
    }

    private async Task RequeueStaleAsync(DateTime now, CancellationToken ct)
    {
        var cutoff = now.AddMinutes(-_options.StaleAfterMinutes);
        var stale = await db.Files
            .Where(f => f.Status == FileSecurityStatus.Validating && f.ValidationStartedAtUtc < cutoff)
            .ToListAsync(ct);
        foreach (var file in stale)
        {
            file.Status = FileSecurityStatus.Pending;
            file.StatusReason = "validation interrupted; requeued";
            file.ConcurrencyStamp = Guid.NewGuid();
            await TrySaveAsync(file, ct);
        }
    }

    private async Task<bool> TrySaveAsync(FileRecord file, CancellationToken ct)
    {
        try
        {
            await db.SaveChangesAsync(ct);
            return true;
        }
        catch (DbUpdateConcurrencyException)
        {
            logger.LogInformation("File {FileId} changed concurrently; skipping", file.Id);
            db.Entry(file).State = EntityState.Detached;
            return false;
        }
    }

    private async Task TryDeleteAsync(StorageArea area, string key)
    {
        try { await storage.DeleteAsync(area, key); }
        catch (Exception ex) { logger.LogWarning(ex, "Could not delete {Area} object {Key}", area, key); }
    }

    private Task LogAsync(string action, bool succeeded, FileRecord file, string details, CancellationToken ct) =>
        audit.LogAsync(action, succeeded, target: file.OriginalFileName, details: details, userEmail: Actor, fileId: file.Id, ct: ct);

    private static string Truncate(string value, int max) => value.Length <= max ? value : value[..max];
}
