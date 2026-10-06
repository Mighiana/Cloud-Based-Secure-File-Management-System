using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using SecureFileUploadPortal.Data;
using SecureFileUploadPortal.Options;
using SecureFileUploadPortal.Services;
using SecureFileUploadPortal.Validation;
using MsOptions = Microsoft.Extensions.Options.Options;

namespace SecureFileUploadPortal.Tests;

internal sealed class TestClock(DateTimeOffset now) : TimeProvider
{
    public DateTimeOffset Now { get; set; } = now;
    public override DateTimeOffset GetUtcNow() => Now;
}

internal static class TestFiles
{
    public static readonly byte[] Pdf = "%PDF-1.7\nhello pdf\n%%EOF"u8.ToArray();
    public static readonly byte[] Exe = [0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
    public static readonly byte[] Png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13];

    // EICAR is the industry-standard harmless antivirus test string, assembled at runtime so the source file itself isn't flagged.
    public static byte[] Eicar => Encoding.ASCII.GetBytes(@"X5O!P%@AP[4\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");

    public static string Sha256(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
}

public class FileSignatureTests
{
    [Theory]
    [InlineData(".pdf", "%PDF-1.4")]
    [InlineData(".PDF", "%PDF-1.4")]
    [InlineData(".txt", "plain text\nline 2")]
    [InlineData(".txt", "")]
    public void Accepts_content_matching_its_extension(string ext, string content) =>
        Assert.Null(FileSignatures.Check(ext, Encoding.ASCII.GetBytes(content)));

    [Fact]
    public void Accepts_binary_signatures()
    {
        Assert.Null(FileSignatures.Check(".png", TestFiles.Png));
        Assert.Null(FileSignatures.Check(".jpg", [0xFF, 0xD8, 0xFF, 0xE0]));
        Assert.Null(FileSignatures.Check(".docx", [0x50, 0x4B, 0x03, 0x04, 0x14]));
    }

    [Theory]
    [InlineData(".pdf")]
    [InlineData(".png")]
    [InlineData(".docx")]
    [InlineData(".txt")]
    public void Rejects_an_executable_renamed_to_an_allowed_extension(string ext) =>
        Assert.Contains("Windows executable", FileSignatures.Check(ext, TestFiles.Exe));

    [Fact]
    public void Rejects_type_confusion_and_binary_text()
    {
        Assert.Contains("PNG image", FileSignatures.Check(".pdf", TestFiles.Png));
        Assert.Contains("does not match", FileSignatures.Check(".pdf", "hello"u8));
        Assert.Contains("binary content", FileSignatures.Check(".txt", "abc\0def"u8));
        Assert.Contains("no signature check", FileSignatures.Check(".svg", "<svg/>"u8));
    }

    [Fact]
    public void Only_verifiable_extensions_can_be_allow_listed() =>
        Assert.Equal([".pdf"], new UploadOptions { AllowedExtensions = [".pdf", ".exe", ".svg"] }.EffectiveExtensions);
}

public class AuditChainTests
{
    private static (AppDbContext Db, AuditService Audit) Create()
    {
        var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        return (db, new AuditService(db, new HttpContextAccessor(), TimeProvider.System, NullLogger<AuditService>.Instance));
    }

    private static async Task<AppDbContext> ChainOfThreeAsync()
    {
        var (db, audit) = Create();
        await audit.LogAsync(AuditActions.LoginSucceeded, true, userEmail: "a@test");
        await audit.LogAsync(AuditActions.FileUploadReceived, true, target: "x.pdf", details: "sha256=abc", userEmail: "a@test", fileId: Guid.NewGuid());
        await audit.LogAsync(AuditActions.Logout, true, userEmail: "a@test");
        db.ChangeTracker.Clear();
        return db;
    }

    [Fact]
    public async Task Entries_are_linked_and_verify()
    {
        var db = await ChainOfThreeAsync();
        var entries = await db.AuditLogs.OrderBy(a => a.Id).ToListAsync();

        Assert.Equal(AuditChain.Genesis, entries[0].PreviousHash);
        Assert.Equal(entries[0].EntryHash, entries[1].PreviousHash);
        Assert.Equal(entries[1].EntryHash, entries[2].PreviousHash);

        var report = await AuditChain.VerifyAsync(db, default);
        Assert.True(report.IsValid);
        Assert.Equal(3, report.VerifiedCount);
        Assert.Equal(entries[2].EntryHash, report.HeadHash);
    }

    [Fact]
    public async Task Detects_a_modified_entry()
    {
        var db = await ChainOfThreeAsync();
        var middle = await db.AuditLogs.OrderBy(a => a.Id).Skip(1).FirstAsync();
        middle.Succeeded = false;
        await db.SaveChangesAsync();

        var report = await AuditChain.VerifyAsync(db, default);
        Assert.False(report.IsValid);
        Assert.Equal(middle.Id, report.BrokenAtId);
        Assert.Contains("modified", report.Problem);
    }

    [Fact]
    public async Task Detects_a_deleted_entry()
    {
        var db = await ChainOfThreeAsync();
        var entries = await db.AuditLogs.OrderBy(a => a.Id).ToListAsync();
        db.AuditLogs.Remove(entries[1]);
        await db.SaveChangesAsync();

        var report = await AuditChain.VerifyAsync(db, default);
        Assert.False(report.IsValid);
        Assert.Equal(entries[2].Id, report.BrokenAtId);
        Assert.Contains("deleted", report.Problem);
    }

    [Fact]
    public async Task Rows_written_before_the_chain_are_reported_as_legacy()
    {
        var (db, audit) = Create();
        db.AuditLogs.Add(new AuditLog { Action = "Legacy", UserEmail = "old@test", Succeeded = true });
        await db.SaveChangesAsync();
        await audit.LogAsync(AuditActions.Logout, true, userEmail: "a@test");

        var report = await AuditChain.VerifyAsync(db, default);
        Assert.True(report.IsValid);
        Assert.Equal(1, report.LegacyCount);
        Assert.Equal(1, report.VerifiedCount);
    }
}

public class ClamAvScannerTests
{
    [Theory]
    [InlineData("stream: OK\0", ScanVerdict.Clean)]
    [InlineData("stream: Eicar-Test-Signature FOUND\0", ScanVerdict.Infected)]
    [InlineData("INSTREAM size limit exceeded. ERROR\0", ScanVerdict.Error)]
    [InlineData("", ScanVerdict.Error)]
    public void Parses_clamd_replies(string reply, ScanVerdict expected) =>
        Assert.Equal(expected, ClamAvSecurityScanner.Parse(reply).Verdict);

    [Fact]
    public void Extracts_the_signature_name() =>
        Assert.Equal("signature Eicar-Test-Signature", ClamAvSecurityScanner.Parse("stream: Eicar-Test-Signature FOUND\0").Detail);

    private static ClamAvSecurityScanner Scanner(string host, int port, int timeout = 5) =>
        new(MsOptions.Create(new ValidationOptions { ClamAv = new ClamAvOptions { Enabled = true, Host = host, Port = port, TimeoutSeconds = timeout } }),
            NullLogger<ClamAvSecurityScanner>.Instance);

    private static FileScanContext Context(byte[] data) =>
        new(new FileRecord { OriginalFileName = "f.txt", SizeBytes = data.Length }, () => new MemoryStream(data));

    [Fact]
    public async Task Unreachable_daemon_is_an_error_not_clean()
    {
        var result = await Scanner("127.0.0.1", 1).ScanAsync(Context("hello"u8.ToArray()), default);
        Assert.Equal(ScanVerdict.Error, result.Verdict);
    }

    /// <summary>Runs against a real clamd when CLAMAV_HOST is set (CI starts one); otherwise there is nothing to test against.</summary>
    [Fact]
    public async Task Real_clamd_detects_the_eicar_test_file()
    {
        if (Environment.GetEnvironmentVariable("CLAMAV_HOST") is not { Length: > 0 } host) return;
        var port = int.Parse(Environment.GetEnvironmentVariable("CLAMAV_PORT") ?? "3310");
        var scanner = Scanner(host, port, 60);

        Assert.Equal(ScanVerdict.Infected, (await scanner.ScanAsync(Context(TestFiles.Eicar), default)).Verdict);
        Assert.Equal(ScanVerdict.Clean, (await scanner.ScanAsync(Context(TestFiles.Pdf), default)).Verdict);
    }
}

public class FileValidationProcessorTests
{
    private sealed class StubScanner(Func<ScanResult> result) : IFileSecurityScanner
    {
        public int Calls { get; private set; }
        public string Name => "stub";
        public Task<ScanResult> ScanAsync(FileScanContext context, CancellationToken ct) { Calls++; return Task.FromResult(result()); }
    }

    private sealed class Harness
    {
        public AppDbContext Db { get; } = new(new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        public FakeStorage Storage { get; } = new();
        public TestClock Clock { get; } = new(new DateTimeOffset(2026, 10, 6, 12, 0, 0, TimeSpan.Zero));
        public List<IFileSecurityScanner> Scanners { get; } = [new BasicFileValidationScanner()];

        public FileValidationProcessor Processor() => new(Db, Storage, Scanners,
            new AuditService(Db, new HttpContextAccessor(), Clock, NullLogger<AuditService>.Instance),
            MsOptions.Create(new ValidationOptions { MaxAttempts = 3, RetryDelaySeconds = 10 }), Clock, NullLogger<FileValidationProcessor>.Instance);

        public async Task<FileRecord> AddAsync(string name, byte[] content, string? storedContent = null)
        {
            var user = new AppUser { Email = $"{Guid.NewGuid():N}@test", DisplayName = "u", PasswordHash = "x" };
            Db.Users.Add(user);
            var key = $"{Guid.NewGuid():N}{Path.GetExtension(name)}";
            Storage.Quarantine[key] = storedContent is null ? content : Encoding.UTF8.GetBytes(storedContent);
            var file = new FileRecord
            {
                StorageKey = key, OriginalFileName = name, ContentType = "application/octet-stream",
                SizeBytes = content.Length, Sha256 = TestFiles.Sha256(content), Owner = user,
            };
            Db.Files.Add(file);
            await Db.SaveChangesAsync();
            return file;
        }

        public async Task<FileRecord> ReloadAsync(Guid id)
        {
            Db.ChangeTracker.Clear();
            return await Db.Files.SingleAsync(f => f.Id == id);
        }

        public Task<List<string>> ActionsAsync(Guid id) =>
            Db.AuditLogs.Where(a => a.FileId == id).OrderBy(a => a.Id).Select(a => a.Action).ToListAsync();
    }

    [Fact]
    public async Task Clean_file_is_approved_and_moved_to_the_approved_bucket()
    {
        var h = new Harness();
        var file = await h.AddAsync("doc.pdf", TestFiles.Pdf);

        Assert.Equal(1, await h.Processor().ProcessPendingAsync(default));

        var result = await h.ReloadAsync(file.Id);
        Assert.Equal(FileSecurityStatus.Approved, result.Status);
        Assert.Equal(StorageArea.Approved, result.StorageArea);
        Assert.True(result.IsDownloadable);
        Assert.True(h.Storage.Approved.ContainsKey(file.StorageKey));
        Assert.False(h.Storage.Quarantine.ContainsKey(file.StorageKey));
        Assert.Equal([AuditActions.FileValidationStarted, AuditActions.FileValidationApproved], await h.ActionsAsync(file.Id));
    }

    [Fact]
    public async Task Object_altered_in_storage_is_rejected_by_hash_check()
    {
        var h = new Harness();
        var file = await h.AddAsync("doc.pdf", TestFiles.Pdf, storedContent: "%PDF-1.7\nHELLO PDF\n%%EOF");

        await h.Processor().ProcessPendingAsync(default);

        var result = await h.ReloadAsync(file.Id);
        Assert.Equal(FileSecurityStatus.Rejected, result.Status);
        Assert.Contains("SHA-256", result.StatusReason);
        Assert.False(h.Storage.Quarantine.ContainsKey(file.StorageKey));
        Assert.Empty(h.Storage.Approved);
    }

    [Fact]
    public async Task Malware_signature_quarantines_and_keeps_the_object_for_review()
    {
        var h = new Harness();
        h.Scanners.Add(new StubScanner(() => ScanResult.Infected("ClamAV", "signature Eicar-Test-Signature")));
        var file = await h.AddAsync("notes.txt", TestFiles.Eicar);

        await h.Processor().ProcessPendingAsync(default);

        var result = await h.ReloadAsync(file.Id);
        Assert.Equal(FileSecurityStatus.Quarantined, result.Status);
        Assert.Equal(StorageArea.Quarantine, result.StorageArea);
        Assert.True(h.Storage.Quarantine.ContainsKey(file.StorageKey));
        Assert.Empty(h.Storage.Approved);
        Assert.Contains(AuditActions.FileQuarantined, await h.ActionsAsync(file.Id));
    }

    [Fact]
    public async Task Scanner_outage_is_retried_then_quarantined_never_approved()
    {
        var h = new Harness();
        var scanner = new StubScanner(() => ScanResult.Error("ClamAV", "clamd unavailable"));
        h.Scanners.Add(scanner);
        var file = await h.AddAsync("doc.pdf", TestFiles.Pdf);

        await h.Processor().ProcessPendingAsync(default);
        var afterFirst = await h.ReloadAsync(file.Id);
        Assert.Equal(FileSecurityStatus.Pending, afterFirst.Status);
        Assert.NotNull(afterFirst.NextAttemptAtUtc);

        // Not due yet: nothing happens.
        Assert.Equal(0, await h.Processor().ProcessPendingAsync(default));

        for (var i = 0; i < 2; i++)
        {
            h.Clock.Now += TimeSpan.FromMinutes(5);
            await h.Processor().ProcessPendingAsync(default);
        }

        var result = await h.ReloadAsync(file.Id);
        Assert.Equal(FileSecurityStatus.Quarantined, result.Status);
        Assert.Equal(3, scanner.Calls);
        Assert.Empty(h.Storage.Approved);
        Assert.Equal(3, (await h.ActionsAsync(file.Id)).Count(a => a == AuditActions.FileScanFailed));
    }

    [Fact]
    public async Task Unreadable_object_fails_closed()
    {
        var h = new Harness();
        var file = await h.AddAsync("doc.pdf", TestFiles.Pdf);
        h.Storage.Quarantine.Remove(file.StorageKey);

        await h.Processor().ProcessPendingAsync(default);

        Assert.Equal(FileSecurityStatus.Pending, (await h.ReloadAsync(file.Id)).Status);
        Assert.Empty(h.Storage.Approved);
    }

    [Fact]
    public async Task Interrupted_validation_is_requeued()
    {
        var h = new Harness();
        var file = await h.AddAsync("doc.pdf", TestFiles.Pdf);
        file.Status = FileSecurityStatus.Validating;
        file.ValidationStartedAtUtc = h.Clock.Now.UtcDateTime.AddMinutes(-30);
        await h.Db.SaveChangesAsync();

        await h.Processor().ProcessPendingAsync(default);

        Assert.Equal(FileSecurityStatus.Approved, (await h.ReloadAsync(file.Id)).Status);
    }
}
