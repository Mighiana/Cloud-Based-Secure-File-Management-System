namespace SecureFileUploadPortal.Services;

public static class FormatHelpers
{
    public static string Ago(DateTime utc, DateTime nowUtc) => (nowUtc - utc) switch
    {
        var d when d.TotalMinutes < 1 => "just now",
        var d when d.TotalHours < 1 => $"{(int)d.TotalMinutes} min ago",
        var d when d.TotalDays < 1 => $"{(int)d.TotalHours} h ago",
        var d => $"{(int)d.TotalDays} d ago",
    };

    public static string Bytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:0.#} KB",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):0.#} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):0.##} GB",
    };
}
