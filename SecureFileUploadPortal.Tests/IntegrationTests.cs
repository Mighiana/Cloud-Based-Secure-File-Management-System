using System.Net;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using SecureFileUploadPortal.Data;
using SecureFileUploadPortal.Services;

namespace SecureFileUploadPortal.Tests;

/// <summary>In-memory stand-in for S3 so the HTTP pipeline can be tested without AWS.</summary>
public sealed class FakeStorage : IFileStorageService
{
    public Dictionary<string, long> Objects { get; } = [];

    public async Task<string> UploadAsync(Stream content, string originalFileName, string contentType, CancellationToken ct = default)
    {
        using var ms = new MemoryStream();
        await content.CopyToAsync(ms, ct);
        var key = Guid.NewGuid().ToString("N");
        Objects[key] = ms.Length;
        return key;
    }

    public Task<IReadOnlyList<StoredObject>> ListAsync(CancellationToken ct = default) =>
        Task.FromResult<IReadOnlyList<StoredObject>>(Objects.Select(o => new StoredObject(o.Key, o.Value, null)).ToList());

    public Task DeleteAsync(string key, CancellationToken ct = default) { Objects.Remove(key); return Task.CompletedTask; }

    public string GetDownloadUrl(string key, string downloadFileName) => $"https://s3.test/{key}?signed";

    public Task<long> GetTotalSizeBytesAsync(CancellationToken ct = default) => Task.FromResult(Objects.Values.Sum());
}

public sealed class PortalFactory : WebApplicationFactory<Program>
{
    public const string AdminEmail = "admin@test.local";
    public const string AdminPassword = "admin-password-123";
    public FakeStorage Storage { get; } = new();
    private readonly string _dbName = Guid.NewGuid().ToString();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Seed:AdminEmail", AdminEmail);
        builder.UseSetting("Seed:AdminPassword", AdminPassword);
        builder.UseSetting("UseHttpsRedirection", "false");
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

    private static async Task<HttpResponseMessage> UploadAsync(HttpClient client, string fileName, string content)
    {
        var token = await AntiforgeryTokenAsync(client, "/File/Upload");
        using var form = new MultipartFormDataContent
        {
            { new StringContent(token), "__RequestVerificationToken" },
            { new ByteArrayContent(System.Text.Encoding.UTF8.GetBytes(content)) { Headers = { ContentType = new("text/html") } }, "file", fileName },
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
        foreach (var url in new[] { "/Admin/Index", "/Admin/Users", "/Admin/Audit", "/Admin/Logs", "/Admin/Reports", "/Admin/Settings" })
            Assert.Equal(HttpStatusCode.OK, (await client.GetAsync(url)).StatusCode);
    }

    [Fact]
    public async Task Upload_stores_object_metadata_and_audit_event()
    {
        await EnsureUserAsync("uma@test.local");
        var client = await SignedInAsync("uma@test.local", "user-password-123");

        var response = await UploadAsync(client, "notes.txt", "hello");

        Assert.Equal(HttpStatusCode.Redirect, response.StatusCode);
        var record = await factory.WithDbAsync(db => db.Files.Include(f => f.Owner).SingleAsync(f => f.OriginalFileName == "notes.txt"));
        Assert.Equal("uma@test.local", record.Owner.Email);
        Assert.Equal(5, record.SizeBytes);
        Assert.Equal("text/plain", record.ContentType);
        Assert.True(factory.Storage.Objects.ContainsKey(record.StorageKey));
        Assert.True(await factory.WithDbAsync(db => db.AuditLogs.AnyAsync(a => a.Action == AuditActions.FileUploaded && a.Target == "notes.txt")));
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
        await UploadAsync(owner, "private.pdf", "secret");
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
        Assert.StartsWith("https://s3.test/", download.Headers.Location!.ToString());
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
