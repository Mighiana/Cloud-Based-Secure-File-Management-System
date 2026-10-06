using Microsoft.Extensions.Options;
using SecureFileUploadPortal.Options;

namespace SecureFileUploadPortal.Validation;

/// <summary>Background loop that drains the Pending queue through <see cref="FileValidationProcessor"/>.</summary>
public sealed class FileValidationWorker(
    IServiceScopeFactory scopes,
    ValidationSignal signal,
    IOptions<ValidationOptions> options,
    ILogger<FileValidationWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var poll = TimeSpan.FromSeconds(Math.Max(1, options.Value.PollSeconds));
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                using var scope = scopes.CreateScope();
                var processed = await scope.ServiceProvider.GetRequiredService<FileValidationProcessor>().ProcessPendingAsync(stoppingToken);
                if (processed > 0) continue;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                logger.LogError(ex, "Validation pass failed");
            }
            await signal.WaitAsync(poll, stoppingToken);
        }
    }
}
