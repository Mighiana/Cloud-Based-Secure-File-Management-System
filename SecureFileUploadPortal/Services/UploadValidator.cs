using Microsoft.Extensions.Options;
using SecureFileUploadPortal.Options;

namespace SecureFileUploadPortal.Services;

public class UploadValidator
{
    private readonly UploadOptions _options;

    public UploadValidator(IOptions<UploadOptions> options) => _options = options.Value;

    /// <summary>Returns an error message, or null when the file is acceptable.</summary>
    public string? Validate(string? fileName, long length)
    {
        if (string.IsNullOrWhiteSpace(fileName) || length <= 0)
            return "Please select a non-empty file.";

        if (length > _options.MaxFileSizeBytes)
            return $"File exceeds the {_options.MaxFileSizeMB} MB limit.";

        var extension = Path.GetExtension(fileName).ToLowerInvariant();
        if (!_options.EffectiveExtensions.Contains(extension, StringComparer.OrdinalIgnoreCase))
            return $"File type '{extension}' is not allowed. Allowed: {string.Join(", ", _options.EffectiveExtensions)}.";

        return null;
    }
}
