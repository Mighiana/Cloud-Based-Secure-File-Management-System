using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureFileUploadPortal.Data;
using SecureFileUploadPortal.Models;
using SecureFileUploadPortal.Options;
using SecureFileUploadPortal.Security;
using SecureFileUploadPortal.Services;
using SecureFileUploadPortal.Validation;

namespace SecureFileUploadPortal.Controllers;

public class FileController(
    AppDbContext db,
    IFileStorageService storage,
    UploadValidator validator,
    AuditService audit,
    ValidationSignal validationSignal,
    IOptions<UploadOptions> uploadOptions,
    ILogger<FileController> logger) : Controller
{
    private static readonly FileExtensionContentTypeProvider ContentTypes = new();

    [HttpGet]
    public IActionResult Upload() => View(new UploadViewModel
    {
        MaxFileSizeMB = uploadOptions.Value.MaxFileSizeMB,
        AllowedExtensions = uploadOptions.Value.EffectiveExtensions,
    });

    /// <summary>
    /// Synchronous checks (size, extension, signature, hash) run before anything is stored; accepted files go to the
    /// quarantine bucket as Pending and only become downloadable once the validation pipeline approves them.
    /// </summary>
    [HttpPost]
    public async Task<IActionResult> Upload(IFormFile? file, CancellationToken ct)
    {
        var fileName = Path.GetFileName(file?.FileName ?? string.Empty);
        if (validator.Validate(fileName, file?.Length ?? 0) is { } error)
            return await RejectUploadAsync(fileName, error, error, ct);

        await using var stream = file!.OpenReadStream();
        var header = await FileSignatures.ReadHeaderAsync(stream, ct);
        if (FileSignatures.Check(Path.GetExtension(fileName), header) is { } mismatch)
            return await RejectUploadAsync(fileName, mismatch, $"The file content does not match its type ({mismatch}).", ct);

        stream.Position = 0;
        var sha256 = Convert.ToHexString(await SHA256.HashDataAsync(stream, ct)).ToLowerInvariant();
        var userId = User.GetUserId()!.Value;

        if (await db.Files.AnyAsync(f => f.Sha256 == sha256 && f.Status == FileSecurityStatus.Quarantined, ct))
            return await RejectUploadAsync(fileName, $"sha256={sha256} matches a quarantined file",
                "This file is identical to one that is quarantined and cannot be uploaded.", ct);

        var duplicate = await db.Files.Where(f => f.OwnerId == userId && f.Sha256 == sha256 && f.Status != FileSecurityStatus.Rejected)
            .Select(f => f.OriginalFileName).FirstOrDefaultAsync(ct);
        if (duplicate is not null)
            return await RejectUploadAsync(fileName, $"duplicate of '{duplicate}' (sha256={sha256})",
                $"You have already uploaded this exact file as '{duplicate}'.", ct);

        string? key = null;
        try
        {
            // The client-supplied Content-Type is not trusted; it is derived from the (already allow-listed) extension.
            var contentType = ContentTypes.TryGetContentType(fileName, out var mapped) ? mapped : "application/octet-stream";
            stream.Position = 0;
            key = await storage.UploadToQuarantineAsync(stream, fileName, contentType, ct);

            var record = new FileRecord
            {
                StorageKey = key,
                OriginalFileName = fileName,
                ContentType = contentType,
                SizeBytes = file.Length,
                Sha256 = sha256,
                OwnerId = userId,
            };
            db.Files.Add(record);
            await db.SaveChangesAsync(ct);

            await audit.LogAsync(AuditActions.FileUploadReceived, true, target: fileName,
                details: $"{FormatHelpers.Bytes(file.Length)}; sha256={sha256}; stored in quarantine", fileId: record.Id, ct: ct);
            validationSignal.Notify();
            TempData["Success"] = $"'{fileName}' uploaded and queued for security validation. It can be downloaded once approved.";
            return RedirectToAction(nameof(List));
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Upload of {FileName} failed", fileName);
            if (key is not null) await TryDeleteOrphanAsync(key);
            await audit.LogAsync(AuditActions.FileUploadFailed, false, target: fileName, ct: CancellationToken.None);
            TempData["Error"] = "The file could not be uploaded. Please try again.";
            return RedirectToAction(nameof(Upload));
        }
    }

    [HttpGet]
    public async Task<IActionResult> List(bool all = false, FileSecurityStatus? status = null, CancellationToken ct = default)
    {
        var isAdmin = User.IsInRole(Roles.Admin);
        var showAll = all && isAdmin;
        var userId = User.GetUserId()!.Value;

        var query = db.Files.AsNoTracking();
        if (!showAll) query = query.Where(f => f.OwnerId == userId);
        if (status is not null) query = query.Where(f => f.Status == status);

        var files = await query.OrderByDescending(f => f.UploadedAtUtc)
            .Select(f => new FileRow(f.Id, f.OriginalFileName, f.ContentType, f.SizeBytes, f.UploadedAtUtc, f.Owner.Email, f.Status))
            .ToListAsync(ct);

        return View(new FileListViewModel { Files = files, ShowAllUsers = showAll, CanSeeAllUsers = isAdmin, StatusFilter = status });
    }

    [HttpGet]
    public async Task<IActionResult> Details(Guid id, CancellationToken ct)
    {
        var file = await FindAccessibleAsync(id, AuditActions.AccessDenied, ct);
        if (file is null) return NotFound();

        return View(new FileDetailsViewModel
        {
            File = file,
            OwnerEmail = await db.Users.Where(u => u.Id == file.OwnerId).Select(u => u.Email).SingleAsync(ct),
            ShowStorageKey = User.IsInRole(Roles.Admin),
            History = await db.AuditLogs.AsNoTracking().Where(a => a.FileId == file.Id)
                .OrderByDescending(a => a.Id).Take(50).ToListAsync(ct),
        });
    }

    /// <summary>The download gate: a pre-signed URL is only issued for Approved files, and only for the approved bucket.</summary>
    [HttpGet]
    public async Task<IActionResult> Download(Guid id, CancellationToken ct)
    {
        var file = await FindAccessibleAsync(id, AuditActions.FileDownloaded, ct);
        if (file is null) return NotFound();

        if (!file.IsDownloadable)
        {
            await audit.LogAsync(AuditActions.DownloadBlockedSecurityState, false, target: file.OriginalFileName,
                details: $"status={file.Status}", fileId: file.Id, ct: ct);
            TempData["Error"] = $"'{file.OriginalFileName}' is {file.Status.ToString().ToLowerInvariant()} and cannot be downloaded.";
            return RedirectToAction(nameof(Details), new { id = file.Id });
        }

        await audit.LogAsync(AuditActions.FileDownloaded, true, target: file.OriginalFileName, fileId: file.Id, ct: ct);
        return Redirect(storage.GetApprovedDownloadUrl(file.StorageKey, file.OriginalFileName));
    }

    [HttpPost]
    public async Task<IActionResult> Delete(Guid id, bool all = false, CancellationToken ct = default)
    {
        var file = await FindAccessibleAsync(id, AuditActions.FileDeleted, ct);
        if (file is null) return NotFound();

        try
        {
            if (file.Status is not FileSecurityStatus.Rejected)
                await storage.DeleteAsync(file.StorageArea, file.StorageKey, ct);
            db.Files.Remove(file);
            await db.SaveChangesAsync(ct);
            await audit.LogAsync(AuditActions.FileDeleted, true, target: file.OriginalFileName, details: $"status={file.Status}", fileId: file.Id, ct: ct);
            TempData["Success"] = $"'{file.OriginalFileName}' deleted.";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Delete of file {FileId} failed", file.Id);
            TempData["Error"] = "The file could not be deleted. Please try again.";
        }
        return RedirectToAction(nameof(List), new { all });
    }

    private async Task<IActionResult> RejectUploadAsync(string fileName, string reason, string message, CancellationToken ct)
    {
        await audit.LogAsync(AuditActions.FileUploadRejected, false, target: fileName, details: reason, ct: ct);
        TempData["Error"] = message;
        return RedirectToAction(nameof(Upload));
    }

    /// <summary>Returns the file only if the caller owns it (or is an admin); denied attempts are audited and look like 404s.</summary>
    private async Task<FileRecord?> FindAccessibleAsync(Guid id, string action, CancellationToken ct)
    {
        var file = await db.Files.SingleOrDefaultAsync(f => f.Id == id, ct);
        if (file is null) return null;
        if (FileAccessPolicy.CanAccess(User, file)) return file;

        await audit.LogAsync(action, false, target: file.OriginalFileName, details: "not owner", fileId: file.Id, ct: ct);
        return null;
    }

    private async Task TryDeleteOrphanAsync(string key)
    {
        try { await storage.DeleteAsync(StorageArea.Quarantine, key); }
        catch (Exception ex) { logger.LogWarning(ex, "Could not remove orphaned object {Key}", key); }
    }
}
