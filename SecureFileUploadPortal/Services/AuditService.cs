using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using SecureFileUploadPortal.Data;

namespace SecureFileUploadPortal.Services;

/// <summary>Appends user and system activity to the AuditLogs hash chain.</summary>
public class AuditService(AppDbContext db, IHttpContextAccessor http, TimeProvider clock, ILogger<AuditService> logger)
{
    // Serialises appends within this process; SQL Server additionally takes an app lock so separate
    // processes (web + standalone validator) cannot fork the chain.
    private static readonly SemaphoreSlim ChainLock = new(1, 1);

    public async Task LogAsync(string action, bool succeeded, string? target = null, string? details = null,
        int? userId = null, string? userEmail = null, Guid? fileId = null, CancellationToken ct = default)
    {
        var context = http.HttpContext;
        var principal = context?.User;
        if (userId is null && int.TryParse(principal?.FindFirstValue(ClaimTypes.NameIdentifier), out var id))
            userId = id;
        userEmail ??= principal?.FindFirstValue(ClaimTypes.Email) ?? "anonymous";

        var entry = new AuditLog
        {
            TimestampUtc = clock.GetUtcNow().UtcDateTime,
            Action = action,
            Succeeded = succeeded,
            UserId = userId,
            UserEmail = Truncate(userEmail, 256)!,
            Target = Truncate(target, 500),
            Details = Truncate(details, 1000),
            IpAddress = ClientIp(context),
            FileId = fileId,
        };

        await ChainLock.WaitAsync(ct);
        try
        {
            if (db.Database.IsRelational())
                await db.Database.CreateExecutionStrategy().ExecuteAsync(() => AppendRelationalAsync(entry, ct));
            else
                await AppendAsync(entry, ct);
        }
        finally
        {
            ChainLock.Release();
        }

        logger.LogInformation("Audit {Action} succeeded={Succeeded} user={User} target={Target}", action, succeeded, userEmail, target);
    }

    private async Task AppendRelationalAsync(AuditLog entry, CancellationToken ct)
    {
        await using var tx = await db.Database.BeginTransactionAsync(ct);
        try
        {
            if (db.Database.IsSqlServer())
                await db.Database.ExecuteSqlRawAsync(
                    "DECLARE @r int; EXEC @r = sp_getapplock @Resource = 'audit-chain', @LockMode = 'Exclusive', @LockOwner = 'Transaction', @LockTimeout = 10000; " +
                    "IF @r < 0 THROW 51000, 'Could not acquire the audit chain lock', 1;", ct);
            await AppendAsync(entry, ct);
            await tx.CommitAsync(ct);
        }
        catch
        {
            db.Entry(entry).State = EntityState.Detached;
            throw;
        }
    }

    private async Task AppendAsync(AuditLog entry, CancellationToken ct)
    {
        entry.PreviousHash = await db.AuditLogs.Where(a => a.EntryHash != null)
            .OrderByDescending(a => a.Id).Select(a => a.EntryHash).FirstOrDefaultAsync(ct) ?? AuditChain.Genesis;
        entry.EntryHash = AuditChain.ComputeHash(entry);
        db.AuditLogs.Add(entry);
        await db.SaveChangesAsync(ct);
    }

    private static string? Truncate(string? value, int max) =>
        value is null || value.Length <= max ? value : value[..max];

    private static string? ClientIp(HttpContext? context)
    {
        var ip = context?.Connection.RemoteIpAddress;
        return (ip is { IsIPv4MappedToIPv6: true } ? ip.MapToIPv4() : ip)?.ToString();
    }
}
