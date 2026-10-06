using System.Security.Claims;
using SecureFileUploadPortal.Data;

namespace SecureFileUploadPortal.Services;

/// <summary>Appends user activity to the AuditLogs table.</summary>
public class AuditService(AppDbContext db, IHttpContextAccessor http, ILogger<AuditService> logger)
{
    public async Task LogAsync(string action, bool succeeded, string? target = null, string? details = null,
        int? userId = null, string? userEmail = null, CancellationToken ct = default)
    {
        var context = http.HttpContext;
        var principal = context?.User;
        if (userId is null && int.TryParse(principal?.FindFirstValue(ClaimTypes.NameIdentifier), out var id))
            userId = id;
        userEmail ??= principal?.FindFirstValue(ClaimTypes.Email) ?? "anonymous";

        db.AuditLogs.Add(new AuditLog
        {
            Action = action,
            Succeeded = succeeded,
            UserId = userId,
            UserEmail = Truncate(userEmail, 256)!,
            Target = Truncate(target, 500),
            Details = Truncate(details, 1000),
            IpAddress = ClientIp(context),
        });
        await db.SaveChangesAsync(ct);

        logger.LogInformation("Audit {Action} succeeded={Succeeded} user={User} target={Target}", action, succeeded, userEmail, target);
    }

    private static string? Truncate(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];

    private static string? ClientIp(HttpContext? context)
    {
        var ip = context?.Connection.RemoteIpAddress;
        return (ip is { IsIPv4MappedToIPv6: true } ? ip.MapToIPv4() : ip)?.ToString();
    }
}
