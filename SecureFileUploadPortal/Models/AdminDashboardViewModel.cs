using System;
using System.Collections.Generic;

namespace SecureFileUploadPortal.Models
{
    public class AdminDashboardViewModel
    {
        // ===== Dashboard Metrics =====
        public int TotalFiles { get; set; } = 0;
        public int TotalAlerts { get; set; } = 0;
        public int TotalUsers { get; set; } = 0; // ✅ Added for Reports view
        public long TotalLogs { get; set; } = 0;
        public long TotalStorageMB { get; set; } = 0;

        // Computed property (read-only)
        public string TotalStorageFormatted => $"{TotalStorageMB} MB";

        // ===== Trends & User Info =====
        public string FilesTrend { get; set; } = "0%";
        public string AlertsTrend { get; set; } = "0%";
        public string LogsTrend { get; set; } = "0%";
        public string CurrentUser { get; set; } = "Admin";
        public DateTime LastLogin { get; set; } = DateTime.Now;

        // ===== Lists =====
        public List<RecentFile> RecentFiles { get; set; } = new List<RecentFile>();
        public List<Alert> Alerts { get; set; } = new List<Alert>();
        public List<TopUser> TopUsers { get; set; } = new List<TopUser>();
        public List<LogEvent> RecentLogs { get; set; } = new List<LogEvent>(); // ✅ Added for Reports view

        // ===== Inner Classes =====
        public class RecentFile
        {
            public string FileName { get; set; } = string.Empty;
            public string User { get; set; } = string.Empty;
            public DateTime UploadTime { get; set; } = DateTime.Now;
            public string Status { get; set; } = "Unknown";
        }

        public class Alert
        {
            public string Severity { get; set; } = "Info";
            public string Message { get; set; } = string.Empty;
            public DateTime Time { get; set; } = DateTime.Now;
            public string Status { get; set; } = "New";
        }

        public class TopUser
        {
            public string UserName { get; set; } = string.Empty;
            public int ActivityCount { get; set; } = 0;
        }

        public class LogEvent
        {
            public string EventName { get; set; } = string.Empty;
            public string UserIdentity { get; set; } = string.Empty;
            public string SourceIPAddress { get; set; } = "0.0.0.0";
            public DateTime EventTime { get; set; } = DateTime.Now;
        }
    }
}
