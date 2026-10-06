using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SecureFileUploadPortal.Data;
using SecureFileUploadPortal.Services;
using SecureFileUploadPortal.Validation;

namespace SecureFileUploadPortal.Tests;

/// <summary>In-memory stand-in for the quarantine and approved S3 buckets so the pipeline can be tested without AWS.</summary>
public sealed class FakeStorage : IFileStorageService
{
    public Dictionary<string, byte[]> Quarantine { get; } = [];
    public Dictionary<string, byte[]> Approved { get; } = [];
    public List<string> PresignedKeys { get; } = [];

    public async Task<string> UploadToQuarantineAsync(Stream content, string originalFileName, string contentType, CancellationToken ct = default)
    {
        using var ms = new MemoryStream();
        await content.CopyToAsync(ms, ct);
        var key = Guid.NewGuid().ToString("N") + Path.GetExtension(originalFileName);
        Quarantine[key] = ms.ToArray();
        return key;
    }

    public Task CopyToApprovedAsync(string key, string contentType, CancellationToken ct = default)
    {
        Approved[key] = Quarantine.TryGetValue(key, out var data) ? data : throw new FileNotFoundException(key);
        return Task.CompletedTask;
    }

    public async Task ReadQuarantinedAsync(string key, Stream destination, CancellationToken ct = default)
    {
        if (!Quarantine.TryGetValue(key, out var data)) throw new FileNotFoundException(key);
        await destination.WriteAsync(data, ct);
    }

    public Task DeleteAsync(StorageArea area, string key, CancellationToken ct = default)
    {
        (area == StorageArea.Approved ? Approved : Quarantine).Remove(key);
        return Task.CompletedTask;
    }

    public string GetApprovedDownloadUrl(string key, string downloadFileName)
    {
        PresignedKeys.Add(key);
        return Approved.ContainsKey(key) ? $"https://s3.test/approved/{key}?signed" : throw new InvalidOperationException("not in approved bucket");
    }
}

public class PortalFactory : WebApplicationFactory<Program>
{
    public const string AdminEmail = "admin@test.local";
    public const string AdminPassword = "admin-password-123";
    public FakeStorage Storage { get; } = new();
    private readonly string _dbName = Guid.NewGuid().ToString();
    protected virtual int LoginAttemptsPerMinute => 1000;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Seed:AdminEmail", AdminEmail);
        builder.UseSetting("Seed:AdminPassword", AdminPassword);
        builder.UseSetting("UseHttpsRedirection", "false");
        // Tests drive validation explicitly via ProcessPendingAsync instead of a background loop.
        builder.UseSetting("Validation:RunWorker", "false");
        // Every test signs in from the same loopback IP; the per-IP login limit is covered separately.
        builder.UseSetting("Security:LoginAttemptsPerMinute", LoginAttemptsPerMinute.ToString());
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<AppDbContext>>();
            services.AddDbContext<AppDbContext>(o => o.UseInMemoryDatabase(_dbName));
            services.RemoveAll<IFileStorageService>();
            services.AddSingleton<IFileStorageService>(Storage);
        });
    }

    public HttpClient CreateBrowser() => CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        BaseAddress = new Uri("https://localhost"),
    });

    public async Task ProcessPendingAsync()
    {
        using var scope = Services.CreateScope();
        await scope.ServiceProvider.GetRequiredService<FileValidationProcessor>().ProcessPendingAsync(default);
    }

    public async Task<T> WithDbAsync<T>(Func<AppDbContext, Task<T>> action)
    {
        using var scope = Services.CreateScope();
        return await action(scope.ServiceProvider.GetRequiredService<AppDbContext>());
    }
}

public class IntegrationTests(PortalFactory factory) : IClassFixture<PortalFactory>
{
    private static async Task<string> AntiforgeryTokenAsync(HttpClient client, string url)
    {
        var html = await client.GetStringAsync(url);
        return Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value;
    }

    private static async Task<HttpResponseMessage> LoginAsync(HttpClient client, string email, string password)
    {
        var token = await AntiforgeryTokenAsync(client, "/Account/Login");
        return await client.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Email"] = email, ["Password"] = password, ["__RequestVerificationToken"] = token,
        }));
    }

    private async Task<HttpClient> SignedInAsync(string email, string password)
    {
        var client = factory.CreateBrowser();
        var response = await LoginAsync(client, email, password);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        return client;
    }

    private async Task EnsureUserAsync(string email, string role = Roles.User)
    {
        using var scope = factory.Services.CreateScope();
        var users = scope.ServiceProvider.GetRequiredService<UserService>();
        await users.CreateAsync(email, email.Split('@')[0], "user-password-123", role);
    }

    private static Task<HttpResponseMessage> UploadAsync(HttpClient client, string fileName, string content) =>
        UploadAsync(client, fileName, System.Text.Encoding.UTF8.GetBytes(content));

    private static async Task<HttpResponseMessage> UploadAsync(HttpClient client, string fileName, byte[] content)
    {
        var token = await AntiforgeryTokenAsync(client, "/File/Upload");
        using var form = new MultipartFormDataContent
        {
            { new StringContent(token), "__RequestVerificationToken" },
            { new ByteArrayContent(content) { Headers = { ContentType = new("text/html") } }, "file", fileName },
        };
        return await client.PostAsync("/File/Upload", form);
    }

    [Theory]
    [InlineData("/")]
    [InlineData("/File/List")]
    [InlineData("/Admin/Index")]
    [InlineData("/Admin/Audit")]
    public async Task Anonymous_requests_are_redirected_to_login(string url)
    {
        var response = await factory.CreateBrowser().GetAsync(url);
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith("/Account/Login", response.Headers.Location!.PathAndQuery);
    }

    [Fact]
    public async Task Health_endpoint_is_public() =>
        Assert.Equal(HttpStatusCode.OK, (await factory.CreateBrowser().GetAsync("/health")).StatusCode);

    [Fact]
    public async Task Login_without_antiforgery_token_is_rejected()
    {
        var response = await factory.CreateBrowser().PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["Email"] = PortalFactory.AdminEmail, ["Password"] = PortalFactory.AdminPassword,
        }));
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Failed_login_is_audited_and_does_not_sign_in()
    {
        var client = factory.CreateBrowser();
        var response = await LoginAsync(client, PortalFactory.AdminEmail, "wrong-password");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Contains("Invalid e-mail or password", await response.Content.ReadAsStringAsync());
        Assert.True(await factory.WithDbAsync(db => db.AuditLogs.AnyAsync(a =>
            a.Action == AuditActions.LoginFailed && a.UserEmail == PortalFactory.AdminEmail && !a.Succeeded)));
    }

    [Fact]
    public async Task Regular_user_is_denied_admin_pages()
    {
        await EnsureUserAsync("ursula@test.local");
        var client = await SignedInAsync("ursula@test.local", "user-password-123");

        var response = await client.GetAsync("/Admin/Users");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith("/Account/AccessDenied", response.Headers.Location!.PathAndQuery);
    }

    [Fact]
    public async Task Admin_can_open_admin_pages()
    {
        var client = await SignedInAsync(PortalFactory.AdminEmail, PortalFactory.AdminPassword);
        foreach (var url in new[] { "/Admin/Index", "/Admin/Users", "/Admin/Audit", "/Admin/Logs", "/Admin/Reports", "/Admin/Settings", "/Admin/Integrity" })
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(url)).StatusCode);
    }

    [Fact]
    public async Task Upload_is_quarantined_as_pending_with_hash_and_audit_event()
    {
        await EnsureUserAsync("uma@test.local");
        var client = await SignedInAsync("uma@test.local", "user-password-123");

        var response = await UploadAsync(client, "notes.txt", "hello");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var record = await factory.WithDbAsync(db => db.Files.Include(f => f.Owner).SingleAsync(f => f.OriginalFileName == "notes.txt"));
        Assert.Equal("uma@test.local", record.Owner.Email);
        Assert.Equal(5, record.SizeBytes);
        Assert.Equal("text/plain", record.ContentType);
        Assert.Equal(FileSecurityStatus.Pending, record.Status);
        Assert.Equal(StorageArea.Quarantine, record.StorageArea);
        Assert.Equal("2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", record.Sha256);
        Assert.True(factory.Storage.Quarantine.ContainsKey(record.StorageKey));
        Assert.False(factory.Storage.Approved.ContainsKey(record.StorageKey));
        Assert.True(await factory.WithDbAsync(db => db.AuditLogs.AnyAsync(a =>
            a.Action == AuditActions.FileUploadReceived && a.FileId == record.Id && a.Details!.Contains(record.Sha256))));
    }

    [Fact]
    public async Task Disallowed_file_type_is_rejected_and_audited()
    {
        await EnsureUserAsync("vic@test.local");
        var client = await SignedInAsync("vic@test.local", "user-password-123");

        await UploadAsync(client, "malware.exe", "MZ");

        Assert.False(await factory.WithDbAsync(db => db.Files.AnyAsync(f => f.OriginalFileName == "malware.exe")));
        Assert.True(await factory.WithDbAsync(db => db.AuditLogs.AnyAsync(a => a.Action == AuditActions.FileUploadRejected && a.Target == "malware.exe")));
    }

    [Fact]
    public async Task Users_cannot_download_or_delete_other_users_files()
    {
        await EnsureUserAsync("owner@test.local");
        await EnsureUserAsync("intruder@test.local");
        var owner = await SignedInAsync("owner@test.local", "user-password-123");
        await UploadAsync(owner, "private.pdf", TestFiles.Pdf);
        await factory.ProcessPendingAsync();
        var fileId = await factory.WithDbAsync(db => db.Files.Where(f => f.OriginalFileName == "private.pdf").Select(f => f.Id).SingleAsync());

        var intruder = await SignedInAsync("intruder@test.local", "user-password-123");
        Assert.Equal(HttpStatusCode.NotFound, (await intruder.GetAsync($"/File/Download/{fileId}")).StatusCode);

        var list = await intruder.GetStringAsync("/File/List");
        Assert.DoesNotContain("private.pdf", list);

        var token = await AntiforgeryTokenAsync(intruder, "/File/Upload");
        var delete = await intruder.PostAsync($"/File/Delete/{fileId}", new FormUrlEncodedContent(new Dictionary<string, string> { ["__RequestVerificationToken"] = token }));
        Assert.Equal(HttpStatusCode.NotFound, delete.StatusCode);
        Assert.True(await factory.WithDbAsync(db => db.Files.AnyAsync(f => f.Id == fileId)));
        Assert.True(await factory.WithDbAsync(db => db.AuditLogs.AnyAsync(a =>
            a.Action == AuditActions.FileDownloaded && !a.Succeeded && a.UserEmail == "intruder@test.local")));

        var download = await owner.GetAsync($"/File/Download/{fileId}");
        Assert.Equal(HttpStatusCode.Redirect, download.StatusCode);
        Assert.StartsWith("https://s3.test/approved/", download.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Executable_renamed_to_pdf_is_rejected_before_storage()
    {
        await EnsureUserAsync("rena@test.local");
        var client = await SignedInAsync("rena@test.local", "user-password-123");
        var before = factory.Storage.Quarantine.Count;

        await UploadAsync(client, "invoice.pdf", TestFiles.Exe);

        Assert.Equal(before, factory.Storage.Quarantine.Count);
        Assert.False(await factory.WithDbAsync(db => db.Files.AnyAsync(f => f.OriginalFileName == "invoice.pdf")));
        Assert.True(await factory.WithDbAsync(db => db.AuditLogs.AnyAsync(a =>
            a.Action == AuditActions.FileUploadRejected && a.Target == "invoice.pdf" && a.Details!.Contains("Windows executable"))));
    }

    [Fact]
    public async Task Pending_file_gets_no_download_url_until_approved()
    {
        await EnsureUserAsync("gate@test.local");
        var client = await SignedInAsync("gate@test.local", "user-password-123");
        await UploadAsync(client, "gated.pdf", TestFiles.Pdf);
        var file = await factory.WithDbAsync(db => db.Files.SingleAsync(f => f.OriginalFileName == "gated.pdf"));

        var blocked = await client.GetAsync($"/File/Download/{file.Id}");
        Assert.Equal(HttpStatusCode.Redirect, blocked.StatusCode);
        Assert.Equal($"/File/Details/{file.Id}", blocked.Headers.Location!.OriginalString);
        Assert.DoesNotContain(file.StorageKey, factory.Storage.PresignedKeys);
        Assert.True(await factory.WithDbAsync(db => db.AuditLogs.AnyAsync(a =>
            a.Action == AuditActions.DownloadBlockedSecurityState && a.FileId == file.Id && a.Details == "status=Pending")));

        await factory.ProcessPendingAsync();

        var allowed = await client.GetAsync($"/File/Download/{file.Id}");
        Assert.StartsWith("https://s3.test/approved/", allowed.Headers.Location!.ToString());
    }

    [Theory]
    [InlineData(FileSecurityStatus.Pending)]
    [InlineData(FileSecurityStatus.Validating)]
    [InlineData(FileSecurityStatus.Rejected)]
    [InlineData(FileSecurityStatus.Quarantined)]
    public async Task Non_approved_states_never_get_a_download_url(FileSecurityStatus status)
    {
        var email = $"state-{status}@test.local".ToLowerInvariant();
        await EnsureUserAsync(email);
        var client = await SignedInAsync(email, "user-password-123");
        await UploadAsync(client, $"{status}.pdf", TestFiles.Pdf.Concat(System.Text.Encoding.ASCII.GetBytes(status.ToString())).ToArray());
        var id = await factory.WithDbAsync(async db =>
        {
            var f = await db.Files.SingleAsync(x => x.OriginalFileName == $"{status}.pdf");
            f.Status = status;
            // Even if the object were somehow in the approved bucket, the status gate must still block it.
            f.StorageArea = StorageArea.Approved;
            factory.Storage.Approved[f.StorageKey] = [1];
            await db.SaveChangesAsync();
            return f.Id;
        });

        var response = await client.GetAsync($"/File/Download/{id}");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.DoesNotContain("s3.test", response.Headers.Location!.ToString());
    }

    [Fact]
    public async Task Duplicate_upload_by_the_same_user_is_rejected()
    {
        await EnsureUserAsync("dup@test.local");
        var client = await SignedInAsync("dup@test.local", "user-password-123");
        await UploadAsync(client, "first.txt", "same bytes");
        await UploadAsync(client, "second.txt", "same bytes");

        Assert.False(await factory.WithDbAsync(db => db.Files.AnyAsync(f => f.OriginalFileName == "second.txt")));
        Assert.True(await factory.WithDbAsync(db => db.AuditLogs.AnyAsync(a =>
            a.Action == AuditActions.FileUploadRejected && a.Target == "second.txt" && a.Details!.StartsWith("duplicate of 'first.txt'"))));
    }

    [Fact]
    public async Task Details_page_shows_hash_to_owner_but_hides_storage_key()
    {
        await EnsureUserAsync("det@test.local");
        await EnsureUserAsync("snoop@test.local");
        var client = await SignedInAsync("det@test.local", "user-password-123");
        await UploadAsync(client, "details.txt", "details content");
        var file = await factory.WithDbAsync(db => db.Files.SingleAsync(f => f.OriginalFileName == "details.txt"));

        var html = await client.GetStringAsync($"/File/Details/{file.Id}");
        Assert.Contains(file.Sha256, html);
        Assert.Contains("Pending", html);
        Assert.DoesNotContain(file.StorageKey, html);

        var admin = await SignedInAsync(PortalFactory.AdminEmail, PortalFactory.AdminPassword);
        Assert.Contains(file.StorageKey, await admin.GetStringAsync($"/File/Details/{file.Id}"));

        var snoop = await SignedInAsync("snoop@test.local", "user-password-123");
        Assert.Equal(HttpStatusCode.NotFound, (await snoop.GetAsync($"/File/Details/{file.Id}")).StatusCode);
    }

    [Fact]
    public async Task Audit_chain_verifies_after_real_traffic()
    {
        var admin = await SignedInAsync(PortalFactory.AdminEmail, PortalFactory.AdminPassword);
        await UploadAsync(admin, "chain.txt", "chain");
        await factory.ProcessPendingAsync();

        Assert.Contains("Chain intact", await admin.GetStringAsync("/Admin/Integrity"));
        var report = await factory.WithDbAsync(db => AuditChain.VerifyAsync(db, default));
        Assert.True(report.IsValid);
    }

    [Fact]
    public async Task Pages_send_a_strict_content_security_policy_and_no_third_party_assets()
    {
        var admin = await SignedInAsync(PortalFactory.AdminEmail, PortalFactory.AdminPassword);
        var response = await admin.GetAsync("/Admin/Index");
        var csp = response.Headers.GetValues("Content-Security-Policy").Single();

        Assert.Contains("default-src 'self'", csp);
        Assert.Contains("script-src 'self'", csp);
        Assert.Contains("frame-ancestors 'none'", csp);
        Assert.DoesNotContain("unsafe-inline", csp);
        var html = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain("<script>", html);
        Assert.DoesNotContain("cdn", html, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Deactivating_a_user_invalidates_their_existing_session()
    {
        await EnsureUserAsync("wendy@test.local");
        var client = await SignedInAsync("wendy@test.local", "user-password-123");
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync("/File/List")).StatusCode);

        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            var users = scope.ServiceProvider.GetRequiredService<UserService>();
            await users.SetActiveAsync(await db.Users.SingleAsync(u => u.Email == "wendy@test.local"), false);
        }

        var response = await client.GetAsync("/File/List");
        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        Assert.StartsWith("/Account/Login", response.Headers.Location!.PathAndQuery);
    }
}

/// <summary>Uses the production default of 10 login attempts per minute per IP.</summary>
public sealed class RateLimitedPortalFactory : PortalFactory
{
    protected override int LoginAttemptsPerMinute => 10;
}

public class LoginRateLimitTests(RateLimitedPortalFactory factory) : IClassFixture<RateLimitedPortalFactory>
{
    [Fact]
    public async Task Login_posts_are_rate_limited_per_ip()
    {
        var client = factory.CreateBrowser();
        var html = await client.GetStringAsync("/Account/Login");
        var token = Regex.Match(html, "name=\"__RequestVerificationToken\" type=\"hidden\" value=\"([^\"]+)\"").Groups[1].Value;
        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 12; i++)
            statuses.Add((await client.PostAsync("/Account/Login", new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["Email"] = $"nobody{i}@test.local", ["Password"] = "wrong-password", ["__RequestVerificationToken"] = token,
            }))).StatusCode);

        Assert.DoesNotContain(HttpStatusCode.TooManyRequests, statuses.Take(10));
        Assert.Equal(HttpStatusCode.TooManyRequests, statuses[^1]);
    }
}
