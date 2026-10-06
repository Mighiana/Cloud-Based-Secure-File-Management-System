using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using SecureFileUploadPortal.Data;

namespace SecureFileUploadPortal.Services;

/// <summary>
/// Tamper-evident (not tamper-proof) hash chain over AuditLogs: each entry's hash covers its fields and the
/// previous entry's hash, so editing or deleting a row inside the chain breaks verification. Someone with
/// write access to the whole table could still rebuild the chain, or drop rows from the end, so the head
/// hash should be recorded outside the database when it matters.
/// </summary>
public static class AuditChain
{
    public static readonly string Genesis = new('0', 64);

    public static string ComputeHash(AuditLog e)
    {
        var canonical = JsonSerializer.Serialize(new object?[]
        {
            e.PreviousHash,
            e.TimestampUtc.ToString("yyyy-MM-dd'T'HH:mm:ss.fffffff", System.Globalization.CultureInfo.InvariantCulture),
            e.UserId,
            e.UserEmail,
            e.Action,
            e.Target,
            e.Details,
            e.IpAddress,
            e.Succeeded,
            e.FileId?.ToString("D"),
        });
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical))).ToLowerInvariant();
    }

    public static async Task<AuditChainReport> VerifyAsync(AppDbContext db, CancellationToken ct)
    {
        int legacy = 0, verified = 0;
        string? expectedPrevious = null;
        AuditLog? last = null;

        await foreach (var entry in db.AuditLogs.AsNoTracking().OrderBy(a => a.Id).AsAsyncEnumerable().WithCancellation(ct))
        {
            if (entry.EntryHash is null)
            {
                if (expectedPrevious is not null)
                    return AuditChainReport.Broken(verified, legacy, entry.Id, "entry has no hash but follows chained entries");
                legacy++;
                continue;
            }

            expectedPrevious ??= Genesis;
            if (entry.PreviousHash != expectedPrevious)
                return AuditChainReport.Broken(verified, legacy, entry.Id, "link to the previous entry is broken (an entry before it was deleted or altered)");
            if (ComputeHash(entry) != entry.EntryHash)
                return AuditChainReport.Broken(verified, legacy, entry.Id, "entry contents do not match its hash (modified after it was written)");

            expectedPrevious = entry.EntryHash;
            verified++;
            last = entry;
        }

        return new AuditChainReport(true, verified, legacy, null, null, last?.Id, last?.EntryHash);
    }
}

public sealed record AuditChainReport(bool IsValid, int VerifiedCount, int LegacyCount, long? BrokenAtId, string? Problem, long? HeadId, string? HeadHash)
{
    public static AuditChainReport Broken(int verified, int legacy, long id, string problem) => new(false, verified, legacy, id, problem, null, null);
}
