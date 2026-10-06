namespace SecureFileUploadPortal.Options;

/// <summary>Post-upload validation pipeline. Bound from the "Validation" configuration section.</summary>
public class ValidationOptions
{
    public const string SectionName = "Validation";

    /// <summary>Run the background validator in this process. Disable to run it as a separate worker with its own IAM role.</summary>
    public bool RunWorker { get; set; } = true;

    public int PollSeconds { get; set; } = 5;
    public int BatchSize { get; set; } = 10;

    /// <summary>Scanner failures are retried this many times; after that the file is quarantined, never approved.</summary>
    public int MaxAttempts { get; set; } = 3;
    public int RetryDelaySeconds { get; set; } = 30;

    /// <summary>A file stuck in Validating longer than this (e.g. worker crash) is put back in the queue.</summary>
    public int StaleAfterMinutes { get; set; } = 5;

    public ClamAvOptions ClamAv { get; set; } = new();
}

public class ClamAvOptions
{
    public bool Enabled { get; set; }
    public string Host { get; set; } = "localhost";
    public int Port { get; set; } = 3310;
    public int TimeoutSeconds { get; set; } = 60;
}
