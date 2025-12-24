using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SecureFileUploadPortal.Models;
using SecureFileUploadPortal.Services;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureFileUploadPortal.Controllers
{
    public class AdminController : Controller
    {
        private readonly S3Service _s3Service;
        private readonly ILogger<AdminController> _logger;
        // Use your real audit bucket/account values
        private readonly string _auditBucket = "trail-bucket2025";
        private readonly string _accountId = "624943132737";

        public AdminController(S3Service s3Service, ILogger<AdminController> logger)
        {
            _s3Service = s3Service;
            _logger = logger;
        }

        // Route: /Admin/Index
        public async Task<IActionResult> Index()
        {
            var model = new AdminDashboardViewModel();
            // Files count
            var files = await _s3Service.ListFilesAsync();
            model.TotalFiles = files?.Count ?? 0;
            // Alerts count (in-memory alert list in S3Service)
            model.TotalAlerts = _s3Service.GetAlerts().Count;
            // Logs count from CloudTrail audit bucket
            model.TotalLogs = (await _s3Service.ListAuditLogsAsync(_auditBucket, _accountId)).Count;
            // Total storage in MB (set backing property, NOT the formatted string)
            var totalStorageMb = await _s3Service.GetTotalStorageSizeAsync();
            model.TotalStorageMB = totalStorageMb; // <-- set this
            // DO NOT assign model.TotalStorageFormatted; it's read-only and computed.
            // Trends & user info (sample / replace with real calculations)
            model.FilesTrend = "↑ 20";
            model.AlertsTrend = "↓ 10";
            model.LogsTrend = "↑ 15";
            model.CurrentUser = "admin-user";
            model.LastLogin = DateTime.Now;
            // Recent files (top 5)
            model.RecentFiles = files?
                .Take(5)
                .Select(k => new AdminDashboardViewModel.RecentFile
                {
                    FileName = k,
                    User = "Unknown",
                    UploadTime = DateTime.Now,
                    Status = "Uploaded"
                }).ToList() ?? new List<AdminDashboardViewModel.RecentFile>();
            // Alerts feed (top 5)
            model.Alerts = _s3Service.GetAlerts()
                .Take(5)
                .Select(a => new AdminDashboardViewModel.Alert
                {
                    Severity = "Info",
                    Message = a,
                    Time = DateTime.Now,
                    Status = "New"
                }).ToList();
            // Top users (dummy)
            model.TopUsers = new List<AdminDashboardViewModel.TopUser>
            {
                new AdminDashboardViewModel.TopUser { UserName = "Alice", ActivityCount = 12 },
                new AdminDashboardViewModel.TopUser { UserName = "Bob", ActivityCount = 10 },
                new AdminDashboardViewModel.TopUser { UserName = "Charlie", ActivityCount = 8 }
            };
            return View(model);
        }

        public async Task<IActionResult> Logs()
        {
            var auditBucket = "trail-bucket2025";
            var accountId = "624943132737";
            var logs = await _s3Service.ListAuditLogsAsync(auditBucket, accountId);
            return View(logs);
        }

        public IActionResult Alerts()
        {
            var alerts = _s3Service.GetAlerts();
            return View(alerts);
        }

        public IActionResult Settings() => View();

        public IActionResult Reports() => View();

        [HttpGet]
        public async Task<IActionResult> GetDashboardData()
        {
            var fileKeys = await _s3Service.ListFilesAsync();
            var alerts = _s3Service.GetAlerts();
            // Mock or fetch real data
            var data = new
            {
                totalFiles = fileKeys?.Count ?? 0,
                filesTrend = "20%",
                totalAlerts = alerts.Count,
                alertsTrend = "10%",
                totalLogs = 241000L,
                logsTrend = "15%",
                recentFiles = fileKeys?.Take(5).Select(key => new { fileName = key, user = "admin", status = "Scanned", uploadTime = DateTime.Now })?.ToArray() ?? new object[0],
                alerts = alerts.Take(5).Select(msg => new { severity = "High", message = msg, time = DateTime.Now, status = "New" }).ToArray(),
                topUsers = new[] { new { userName = "jsmith", activityCount = 45 }, new { userName = "admin", activityCount = 12 } },
                filesData = new { labels = new[] { "Mon", "Tue", "Wed", "Thu", "Fri" }, data = new[] { 1, 2, 1, 3, 2 } },
                alertsData = new { labels = new[] { "Mon", "Tue", "Wed", "Thu", "Fri" }, data = new[] { 5, 3, 2, 1, 0 } },
                logsData = new { labels = new[] { "Mon", "Tue", "Wed", "Thu", "Fri" }, data = new[] { 100, 150, 200, 180, 241 } },
                activityData = new
                {
                    labels = new[] { "00:00", "04:00", "08:00", "12:00", "16:00", "20:00" },
                    uploads = new[] { 12, 19, 3, 5, 2, 3 },
                    logins = new[] { 2, 15, 8, 10, 6, 4 },
                    errors = new[] { 1, 0, 2, 1, 0, 0 }
                },
                cloudWatchData = new { labels = new[] { "1min ago", "2min ago", "3min ago", "4min ago", "5min ago" }, data = new[] { 5, 8, 3, 12, 7 } } // New for CloudWatch
            };
            return Json(data);
        }

        // View/Download log
        public async Task<IActionResult> ViewLog(string key)
        {
            if (string.IsNullOrEmpty(key))
            {
                TempData["Error"] = "Invalid log key.";
                return RedirectToAction("Logs");
            }
            try
            {
                var content = await _s3Service.GetAuditLogContentAsync(_auditBucket, key); // Decompressed string
                var fileName = Path.GetFileName(key).Replace(".gz", ".json"); // e.g., "log.json"
                var bytes = Encoding.UTF8.GetBytes(content);
                return File(bytes, "application/json", fileName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error downloading log: {Key}", key);
                TempData["Error"] = $"Unable to download log: {ex.Message}";
                return RedirectToAction("Logs");
            }
        }


        [HttpGet]
        public async Task<IActionResult> GetReportData()
        {
            var storageMb = await _s3Service.GetTotalStorageSizeAsync();
            double percent = (double)storageMb / 1000 * 100;

            // Prevent overflow
            if (percent > 100) percent = 100;

            var data = new
            {
                storageFormatted = $"{storageMb} MB",
                storagePercent = percent.ToString("F0")
            };
            return Json(data);
        }

        [HttpGet]
        public async Task<IActionResult> DownloadReport(string type)
        {
            try
            {
                var sb = new StringBuilder();
                var fileName = $"{type}_report_{DateTime.UtcNow:yyyyMMddHHmmss}.csv";

                if (type == "uploads")
                {
                    var files = await _s3Service.ListFilesAsync();
                    sb.AppendLine("FileName,UploadedBy,UploadDate");
                    foreach (var file in files)
                        sb.AppendLine($"{file},admin,{DateTime.UtcNow}");
                }
                else if (type == "logs")
                {
                    var logs = await _s3Service.ListAuditLogsAsync(_auditBucket, _accountId);
                    sb.AppendLine("LogKey,Date");
                    foreach (var log in logs)
                        sb.AppendLine($"{log},{DateTime.UtcNow}");
                }
                else if (type == "audit")
                {
                    sb.AppendLine("User,Action,Timestamp,Status");
                    sb.AppendLine("admin,SecurityReview,2025-11-10,Passed");
                }
                else
                {
                    return BadRequest("Invalid report type.");
                }

                var bytes = Encoding.UTF8.GetBytes(sb.ToString());
                return File(bytes, "text/csv", fileName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error generating report for type: {Type}", type);
                TempData["Error"] = $"Error generating report: {ex.Message}";
                return RedirectToAction("Reports");
            }
        }




    }
}