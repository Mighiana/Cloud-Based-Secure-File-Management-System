using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureFileUploadPortal.Data;
using SecureFileUploadPortal.Models;
using SecureFileUploadPortal.Options;
using SecureFileUploadPortal.Security;
using SecureFileUploadPortal.Services;

namespace SecureFileUploadPortal.Controllers;

public class FileController(
    AppDbContext db,
    IFileStorageService storage,
    UploadValidator validator,
    AuditService audit,
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

    [HttpPost]
    public async Task<IActionResult> Upload(IFormFile? file, CancellationToken ct)
    {
        var fileName = Path.GetFileName(file?.FileName ?? string.Empty);
        if (validator.Validate(fileName, file?.Length ?? 0) is { } error)
        {
            await audit.LogAsync(AuditActions.FileUploadRejected, false, target: fileName, details: error, ct: ct);
            TempData["Error"] = error;
            return RedirectToAction(nameof(Upload));
        }

        string? key = null;
        try
        {
            // The client-supplied Content-Type is not trusted; it is derived from the (already allow-listed) extension.
            var contentType = ContentTypes.TryGetContentType(fileName, out var mapped) ? mapped : "application/octet-stream";
            await using var stream = file!.OpenReadStream();
            key = await storage.UploadAsync(stream, fileName, contentType, ct);

            var record = new FileRecord
            {
                StorageKey = key,
                OriginalFileName = fileName,
                ContentType = contentType,
                SizeBytes = file.Length,
                OwnerId = User.GetUserId()!.Value,
            };
            db.Files.Add(record);
            await db.SaveChangesAsync(ct);

            await audit.LogAsync(AuditActions.FileUploaded, true, target: fileName, details: $"id={record.Id}; {FormatHelpers.Bytes(file.Length)}", ct: ct);
            TempData["Success"] = $"'{fileName}' uploaded.";
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
    public async Task<IActionResult> List(bool all = false, CancellationToken ct = default)
    {
        var isAdmin = User.IsInRole(Roles.Admin);
        var showAll = all && isAdmin;
        var userId = User.GetUserId()!.Value;

        var query = db.Files.AsNoTracking();
        if (!showAll) query = query.Where(f => f.OwnerId == userId);

        var files = await query.OrderByDescending(f => f.UploadedAtUtc)
            .Select(f => new FileRow(f.Id, f.OriginalFileName, f.ContentType, f.SizeBytes, f.UploadedAtUtc, f.Owner.Email))
            .ToListAsync(ct);

        return View(new FileListViewModel { Files = files, ShowAllUsers = showAll, CanSeeAllUsers = isAdmin });
    }

    [HttpGet]
    public async Task<IActionResult> Download(Guid id, CancellationToken ct)
    {
        var file = await FindAccessibleAsync(id, AuditActions.FileDownloaded, ct);
        if (file is null) return NotFound();

        await audit.LogAsync(AuditActions.FileDownloaded, true, target: file.OriginalFileName, details: $"id={file.Id}", ct: ct);
        return Redirect(storage.GetDownloadUrl(file.StorageKey, file.OriginalFileName));
    }

    [HttpPost]
    public async Task<IActionResult> Delete(Guid id, bool all = false, CancellationToken ct = default)
    {
        var file = await FindAccessibleAsync(id, AuditActions.FileDeleted, ct);
        if (file is null) return NotFound();

        try
        {
            await storage.DeleteAsync(file.StorageKey, ct);
            db.Files.Remove(file);
            await db.SaveChangesAsync(ct);
            await audit.LogAsync(AuditActions.FileDeleted, true, target: file.OriginalFileName, details: $"id={file.Id}", ct: ct);
            TempData["Success"] = $"'{file.OriginalFileName}' deleted.";
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Delete of file {FileId} failed", file.Id);
            TempData["Error"] = "The file could not be deleted. Please try again.";
        }
        return RedirectToAction(nameof(List), new { all });
    }

    /// <summary>Returns the file only if the caller owns it (or is an admin); denied attempts are audited and look like 404s.</summary>
    private async Task<FileRecord?> FindAccessibleAsync(Guid id, string action, CancellationToken ct)
    {
        var file = await db.Files.SingleOrDefaultAsync(f => f.Id == id, ct);
        if (file is null) return null;
        if (FileAccessPolicy.CanAccess(User, file)) return file;

        await audit.LogAsync(action, false, target: file.OriginalFileName, details: $"id={file.Id}; not owner", ct: ct);
        return null;
    }

    private async Task TryDeleteOrphanAsync(string key)
    {
        try { await storage.DeleteAsync(key); }
        catch (Exception ex) { logger.LogWarning(ex, "Could not remove orphaned object {Key}", key); }
    }
}
