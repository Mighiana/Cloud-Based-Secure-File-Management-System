using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureFileUploadPortal.Data;
using SecureFileUploadPortal.Models;
using SecureFileUploadPortal.Options;
using SecureFileUploadPortal.Security;
using SecureFileUploadPortal.Services;

namespace SecureFileUploadPortal.Controllers;

[Authorize(Roles = Roles.Admin)]
public class AdminController(
    AppDbContext db,
    UserService users,
    AuditService audit,
    CloudTrailLogService cloudTrail,
    IOptions<StorageOptions> storageOptions,
    IOptions<UploadOptions> uploadOptions,
    IOptions<CloudTrailOptions> cloudTrailOptions,
    IWebHostEnvironment env,
    TimeProvider clock,
    ILogger<AdminController> logger) : Controller
{
    public async Task<IActionResult> Index(CancellationToken ct)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var since24h = now.AddHours(-24);
        var firstDay = now.Date.AddDays(-6);

        var weekEvents = await db.AuditLogs.AsNoTracking()
            .Where(a => a.TimestampUtc >= firstDay)
            .Select(a => new { a.TimestampUtc, a.Action, a.Succeeded, a.UserEmail })
            .ToListAsync(ct);

        int Count(DateTime day, string action, bool succeeded) =>
            weekEvents.Count(e => e.TimestampUtc.Date == day && e.Action == action && e.Succeeded == succeeded);

        var model = new AdminDashboardViewModel
        {
            TotalUsers = await db.Users.CountAsync(ct),
            ActiveUsers = await db.Users.CountAsync(u => u.IsActive, ct),
            TotalFiles = await db.Files.CountAsync(ct),
            StorageBytes = await db.Files.SumAsync(f => (long?)f.SizeBytes, ct) ?? 0,
            FailedLogins24h = await db.AuditLogs.CountAsync(a => a.TimestampUtc >= since24h &&
                (a.Action == AuditActions.LoginFailed || a.Action == AuditActions.LoginLockedOut), ct),
            Events24h = await db.AuditLogs.CountAsync(a => a.TimestampUtc >= since24h, ct),
            Last7Days = Enumerable.Range(0, 7).Select(i => firstDay.AddDays(i)).Select(d => new DailyActivity(
                d.ToString("ddd dd"),
                Count(d, AuditActions.FileUploaded, true),
                Count(d, AuditActions.FileDownloaded, true),
                Count(d, AuditActions.LoginSucceeded, true),
                Count(d, AuditActions.LoginFailed, false) + Count(d, AuditActions.LoginLockedOut, false))).ToList(),
            RecentEvents = await db.AuditLogs.AsNoTracking().OrderByDescending(a => a.TimestampUtc).Take(8).ToListAsync(ct),
            RecentFiles = await db.Files.AsNoTracking().OrderByDescending(f => f.UploadedAtUtc).Take(5)
                .Select(f => new FileRow(f.Id, f.OriginalFileName, f.ContentType, f.SizeBytes, f.UploadedAtUtc, f.Owner.Email))
                .ToListAsync(ct),
            TopUsers = weekEvents.Where(e => e.UserEmail != "anonymous")
                .GroupBy(e => e.UserEmail)
                .Select(g => new UserActivity(g.Key, g.Count()))
                .OrderByDescending(u => u.Events).Take(5).ToList(),
        };
        return View(model);
    }

    // ---------- Users ----------

    [HttpGet]
    public async Task<IActionResult> Users(CancellationToken ct) => View(await BuildUsersModelAsync(new CreateUserInput(), ct));

    [HttpPost]
    public async Task<IActionResult> CreateUser([Bind(Prefix = "NewUser")] CreateUserInput input, CancellationToken ct)
    {
        if (!ModelState.IsValid) return View(nameof(Users), await BuildUsersModelAsync(input, ct));

        var (user, error) = await users.CreateAsync(input.Email, input.DisplayName, input.Password, input.Role, ct);
        if (user is null)
        {
            ModelState.AddModelError(string.Empty, error!);
            input.Password = string.Empty;
            return View(nameof(Users), await BuildUsersModelAsync(input, ct));
        }

        await audit.LogAsync(AuditActions.UserCreated, true, target: user.Email, details: $"role={user.Role}", ct: ct);
        TempData["Success"] = $"User {user.Email} created.";
        return RedirectToAction(nameof(Users));
    }

    [HttpPost]
    public async Task<IActionResult> SetRole(int id, string role, CancellationToken ct)
    {
        var user = await FindOtherUserAsync(id, ct);
        if (user is null) return RedirectToAction(nameof(Users));
        if (!Roles.All.Contains(role)) return BadRequest();

        var previous = user.Role;
        await users.SetRoleAsync(user, role, ct);
        await audit.LogAsync(AuditActions.UserRoleChanged, true, target: user.Email, details: $"{previous} -> {role}", ct: ct);
        TempData["Success"] = $"{user.Email} is now {role}.";
        return RedirectToAction(nameof(Users));
    }

    [HttpPost]
    public async Task<IActionResult> SetActive(int id, bool active, CancellationToken ct)
    {
        var user = await FindOtherUserAsync(id, ct);
        if (user is null) return RedirectToAction(nameof(Users));

        await users.SetActiveAsync(user, active, ct);
        await audit.LogAsync(active ? AuditActions.UserActivated : AuditActions.UserDeactivated, true, target: user.Email, ct: ct);
        TempData["Success"] = $"{user.Email} {(active ? "activated" : "deactivated")}.";
        return RedirectToAction(nameof(Users));
    }

    /// <summary>Admins cannot change their own role or status, so the last admin can't lock everyone out.</summary>
    private async Task<AppUser?> FindOtherUserAsync(int id, CancellationToken ct)
    {
        if (id == User.GetUserId())
        {
            TempData["Error"] = "You cannot change your own role or status.";
            return null;
        }
        var user = await db.Users.SingleOrDefaultAsync(u => u.Id == id, ct);
        if (user is null) TempData["Error"] = "User not found.";
        return user;
    }

    private async Task<UsersViewModel> BuildUsersModelAsync(CreateUserInput input, CancellationToken ct)
    {
        var now = clock.GetUtcNow().UtcDateTime;
        var rows = await db.Users.AsNoTracking().OrderBy(u => u.Email)
            .Select(u => new UserRow(u.Id, u.Email, u.DisplayName, u.Role, u.IsActive, u.CreatedAtUtc, u.LastLoginAtUtc,
                u.Files.Count, u.LockoutEndUtc != null && u.LockoutEndUtc > now))
            .ToListAsync(ct);
        return new UsersViewModel { Users = rows, NewUser = input, CurrentUserId = User.GetUserId() ?? 0 };
    }

    // ---------- Audit log ----------

    [HttpGet]
    public async Task<IActionResult> Audit([FromQuery] AuditFilter filter, CancellationToken ct)
    {
        var query = ApplyFilter(db.AuditLogs.AsNoTracking(), filter);
        var total = await query.CountAsync(ct);
        filter.Page = Math.Clamp(filter.Page, 1, Math.Max(1, (int)Math.Ceiling(total / (double)AuditViewModel.PageSize)));

        return View(new AuditViewModel
        {
            Filter = filter,
            TotalCount = total,
            Entries = await query.OrderByDescending(a => a.TimestampUtc)
                .Skip((filter.Page - 1) * AuditViewModel.PageSize).Take(AuditViewModel.PageSize).ToListAsync(ct),
            KnownActions = typeof(AuditActions).GetFields().Select(f => (string)f.GetValue(null)!).Order().ToList(),
        });
    }

    internal static IQueryable<AuditLog> ApplyFilter(IQueryable<AuditLog> query, AuditFilter filter)
    {
        if (!string.IsNullOrWhiteSpace(filter.Action)) query = query.Where(a => a.Action == filter.Action);
        if (!string.IsNullOrWhiteSpace(filter.User)) query = query.Where(a => a.UserEmail.Contains(filter.User.Trim()));
        if (filter.Succeeded is { } ok) query = query.Where(a => a.Succeeded == ok);
        return query;
    }

    // ---------- CloudTrail ----------

    [HttpGet]
    public async Task<IActionResult> Logs(CancellationToken ct)
    {
        if (!cloudTrail.IsConfigured) return View(new CloudTrailViewModel { IsConfigured = false });
        try
        {
            var logs = await cloudTrail.ListAsync(ct);
            return View(new CloudTrailViewModel
            {
                IsConfigured = true,
                Logs = logs.Select(l => new CloudTrailRow(l.Key, l.SizeBytes, l.LastModifiedUtc)).ToList(),
            });
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Listing CloudTrail logs failed");
            return View(new CloudTrailViewModel { IsConfigured = true, Error = "CloudTrail logs could not be listed. Check the bucket name and IAM permissions." });
        }
    }

    [HttpGet]
    public async Task<IActionResult> ViewLog(string key, CancellationToken ct)
    {
        if (!cloudTrail.IsValidKey(key))
        {
            TempData["Error"] = "Invalid log key.";
            return RedirectToAction(nameof(Logs));
        }
        try
        {
            var content = await cloudTrail.ReadAsync(key, ct);
            await audit.LogAsync(AuditActions.CloudTrailLogViewed, true, target: key, ct: ct);
            var fileName = Path.GetFileName(key).Replace(".json.gz", ".json");
            return File(Encoding.UTF8.GetBytes(content), "application/json", fileName);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            logger.LogError(ex, "Reading CloudTrail log {Key} failed", key);
            TempData["Error"] = "The log file could not be read.";
            return RedirectToAction(nameof(Logs));
        }
    }

    // ---------- Reports ----------

    [HttpGet]
    public async Task<IActionResult> Reports(CancellationToken ct) => View(new ReportsViewModel
    {
        StorageBytes = await db.Files.SumAsync(f => (long?)f.SizeBytes, ct) ?? 0,
        StorageQuotaMB = storageOptions.Value.StorageQuotaMB,
        CloudTrailConfigured = cloudTrail.IsConfigured,
    });

    [HttpGet]
    public async Task<IActionResult> DownloadReport(string type, CancellationToken ct)
    {
        var csv = new CsvBuilder();
        switch (type)
        {
            case "files":
                csv.Row("FileId", "FileName", "ContentType", "SizeBytes", "Owner", "UploadedUtc");
                foreach (var f in await db.Files.AsNoTracking().OrderByDescending(f => f.UploadedAtUtc)
                             .Select(f => new { f.Id, f.OriginalFileName, f.ContentType, f.SizeBytes, f.Owner.Email, f.UploadedAtUtc }).ToListAsync(ct))
                    csv.Row(f.Id, f.OriginalFileName, f.ContentType, f.SizeBytes, f.Email, f.UploadedAtUtc);
                break;

            case "audit":
                csv.Row("TimestampUtc", "User", "Action", "Succeeded", "Target", "Details", "IpAddress");
                foreach (var a in await db.AuditLogs.AsNoTracking().OrderByDescending(a => a.TimestampUtc).Take(50_000).ToListAsync(ct))
                    csv.Row(a.TimestampUtc, a.UserEmail, a.Action, a.Succeeded, a.Target, a.Details, a.IpAddress);
                break;

            case "cloudtrail" when cloudTrail.IsConfigured:
                csv.Row("LogKey", "SizeBytes", "LastModifiedUtc");
                try
                {
                    foreach (var l in await cloudTrail.ListAsync(ct)) csv.Row(l.Key, l.SizeBytes, l.LastModifiedUtc);
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    logger.LogError(ex, "CloudTrail report failed");
                    TempData["Error"] = "CloudTrail logs could not be listed.";
                    return RedirectToAction(nameof(Reports));
                }
                break;

            default:
                return BadRequest("Unknown report type.");
        }

        await audit.LogAsync(AuditActions.ReportExported, true, target: type, ct: ct);
        return File(csv.ToBytes(), "text/csv", $"{type}_report_{clock.GetUtcNow():yyyyMMddHHmmss}.csv");
    }

    // ---------- Settings (read-only) ----------

    [HttpGet]
    public IActionResult Settings()
    {
        var s = storageOptions.Value;
        var u = uploadOptions.Value;
        return View(new SettingsViewModel
        {
            StorageEndpoint = string.IsNullOrWhiteSpace(s.ServiceUrl) ? $"AWS S3 ({s.Region})" : s.ServiceUrl,
            BucketName = s.BucketName,
            Region = s.Region,
            ServerSideEncryption = s.ServerSideEncryption,
            KmsKeyConfigured = !string.IsNullOrWhiteSpace(s.KmsKeyId),
            PresignedUrlMinutes = s.PresignedUrlMinutes,
            MaxFileSizeMB = u.MaxFileSizeMB,
            AllowedExtensions = u.EffectiveExtensions,
            CloudTrailBucket = cloudTrailOptions.Value.BucketName,
            StaticCredentials = !string.IsNullOrWhiteSpace(s.AccessKey),
            Environment = env.EnvironmentName,
        });
    }
}
