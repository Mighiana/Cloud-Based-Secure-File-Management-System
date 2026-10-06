using System.Diagnostics;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using SecureFileUploadPortal.Data;
using SecureFileUploadPortal.Models;
using SecureFileUploadPortal.Security;

namespace SecureFileUploadPortal.Controllers;

public class HomeController(AppDbContext db) : Controller
{
    /// <summary>Personal dashboard: the signed-in user's own files and activity.</summary>
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var userId = User.GetUserId()!.Value;
        var user = await db.Users.AsNoTracking().SingleAsync(u => u.Id == userId, ct);
        var files = db.Files.AsNoTracking().Where(f => f.OwnerId == userId);

        var model = new UserDashboardViewModel
        {
            DisplayName = user.DisplayName,
            FileCount = await files.CountAsync(ct),
            StorageBytes = await files.SumAsync(f => (long?)f.SizeBytes, ct) ?? 0,
            LastLoginUtc = user.LastLoginAtUtc,
            RecentFiles = await files.OrderByDescending(f => f.UploadedAtUtc).Take(5)
                .Select(f => new FileRow(f.Id, f.OriginalFileName, f.ContentType, f.SizeBytes, f.UploadedAtUtc, user.Email))
                .ToListAsync(ct),
            RecentActivity = await db.AuditLogs.AsNoTracking().Where(a => a.UserId == userId)
                .OrderByDescending(a => a.TimestampUtc).Take(8).ToListAsync(ct),
        };
        return View(model);
    }

    [AllowAnonymous, ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error() =>
        View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });

    [AllowAnonymous, Route("/Home/StatusCode")]
    public IActionResult StatusCodePage(int code)
    {
        ViewData["StatusCode"] = code;
        return View("StatusCode");
    }
}
