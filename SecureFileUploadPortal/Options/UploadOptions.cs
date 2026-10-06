namespace SecureFileUploadPortal.Options;

/// <summary>Server-side upload restrictions. Bound from the "Upload" configuration section.</summary>
public class UploadOptions
{
    public const string SectionName = "Upload";

    public int MaxFileSizeMB { get; set; } = 50;
    public static readonly string[] DefaultExtensions = [".pdf", ".docx", ".xlsx", ".txt", ".png", ".jpg", ".jpeg"];

    // No initializer: the configuration binder appends to existing arrays, which would duplicate entries.
    public string[] AllowedExtensions { get; set; } = [];

    public string[] EffectiveExtensions => (AllowedExtensions.Length == 0 ? DefaultExtensions : AllowedExtensions)
        .Select(e => e.Trim().ToLowerInvariant()).Where(e => e.Length > 0).Distinct().ToArray();

    public long MaxFileSizeBytes => MaxFileSizeMB * 1024L * 1024L;
}
