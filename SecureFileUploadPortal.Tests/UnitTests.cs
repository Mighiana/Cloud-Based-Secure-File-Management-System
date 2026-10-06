using Microsoft.Extensions.Configuration;
using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureFileUploadPortal.Data;
using SecureFileUploadPortal.Options;
using SecureFileUploadPortal.Security;
using SecureFileUploadPortal.Services;

namespace SecureFileUploadPortal.Tests;

public class UploadValidatorTests
{
    private static UploadValidator Create(int maxMb = 1) =>
        new(Microsoft.Extensions.Options.Options.Create(new UploadOptions { MaxFileSizeMB = maxMb, AllowedExtensions = [".pdf", ".png"] }));

    [Theory]
    [InlineData(null, 10)]
    [InlineData("", 10)]
    [InlineData("a.pdf", 0)]
    public void Rejects_missing_or_empty_files(string? name, long length) =>
        Assert.NotNull(Create().Validate(name, length));

    [Fact]
    public void Rejects_files_over_the_limit() =>
        Assert.Contains("1 MB", Create().Validate("a.pdf", 1024 * 1024 + 1));

    [Theory]
    [InlineData("payload.exe")]
    [InlineData("script.pdf.js")]
    [InlineData("noextension")]
    public void Rejects_disallowed_extensions(string name) =>
        Assert.Contains("not allowed", Create().Validate(name, 10));

    [Theory]
    [InlineData("report.pdf")]
    [InlineData("PHOTO.PNG")]
    public void Accepts_allowed_files_case_insensitively(string name) =>
        Assert.Null(Create().Validate(name, 1024));
}

public class CsvBuilderTests
{
    [Theory]
    [InlineData("plain", "plain")]
    [InlineData("a,b", "\"a,b\"")]
    [InlineData("say \"hi\"", "\"say \"\"hi\"\"\"")]
    [InlineData("=HYPERLINK(\"x\")", "\"'=HYPERLINK(\"\"x\"\")\"")]
    [InlineData("+1", "'+1")]
    [InlineData("@cmd", "'@cmd")]
    public void Escapes_values_and_neutralises_formulas(string input, string expected) =>
        Assert.Equal(expected, CsvBuilder.Escape(input));

    [Fact]
    public void Formats_dates_as_invariant_utc() =>
        Assert.Equal("2025-01-02 03:04:05Z", CsvBuilder.Escape(new DateTime(2025, 1, 2, 3, 4, 5, DateTimeKind.Utc)));
}

public class FileAccessPolicyTests
{
    private static ClaimsPrincipal Principal(int id, string role) => new(new ClaimsIdentity(
        [new Claim(ClaimTypes.NameIdentifier, id.ToString()), new Claim(ClaimTypes.Role, role)], "test"));

    [Fact]
    public void Owner_can_access_own_file() =>
        Assert.True(FileAccessPolicy.CanAccess(Principal(7, Roles.User), new FileRecord { OwnerId = 7 }));

    [Fact]
    public void User_cannot_access_someone_elses_file() =>
        Assert.False(FileAccessPolicy.CanAccess(Principal(7, Roles.User), new FileRecord { OwnerId = 8 }));

    [Fact]
    public void Admin_can_access_any_file() =>
        Assert.True(FileAccessPolicy.CanAccess(Principal(1, Roles.Admin), new FileRecord { OwnerId = 8 }));

    [Fact]
    public void Unauthenticated_principal_cannot_access_files() =>
        Assert.False(FileAccessPolicy.CanAccess(new ClaimsPrincipal(new ClaimsIdentity()), new FileRecord { OwnerId = 8 }));
}

public class CloudTrailKeyTests
{
    private static readonly CloudTrailLogService Service = new(
        new Amazon.S3.AmazonS3Client(new Amazon.Runtime.AnonymousAWSCredentials(), Amazon.RegionEndpoint.EUCentral1),
        Microsoft.Extensions.Options.Options.Create(new CloudTrailOptions { BucketName = "trail", AccountId = "111122223333" }));

    [Theory]
    [InlineData("AWSLogs/111122223333/CloudTrail/eu-central-1/2025/01/01/log.json.gz", true)]
    [InlineData("AWSLogs/999999999999/CloudTrail/eu-central-1/2025/01/01/log.json.gz", false)]
    [InlineData("AWSLogs/111122223333/CloudTrail/../../secret.json.gz", false)]
    [InlineData("AWSLogs/111122223333/CloudTrail/eu-central-1/notes.txt", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void Only_keys_under_the_configured_prefix_are_valid(string? key, bool expected) =>
        Assert.Equal(expected, Service.IsValidKey(key));
}

public class DownloadHeaderTests
{
    [Theory]
    [InlineData("report.pdf", "report.pdf")]
    [InlineData("a\"b\r\n.pdf", "ab.pdf")]
    [InlineData("\u00e9\u00e9", "download")]
    public void Sanitises_content_disposition_file_names(string input, string expected) =>
        Assert.Equal(expected, S3FileStorageService.SanitizeHeaderFileName(input));
}

public class AuditDisplayTests
{
    [Fact]
    public void Splits_action_names_into_words() =>
        Assert.Equal("Login Failed", AuditDisplay.Label(AuditActions.LoginFailed));
}

public class UserServiceTests
{
    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public DateTimeOffset Now { get; set; } = now;
        public override DateTimeOffset GetUtcNow() => Now;
    }

    private static (UserService Service, AppDbContext Db, FixedClock Clock) Create()
    {
        var db = new AppDbContext(new DbContextOptionsBuilder<AppDbContext>().UseInMemoryDatabase(Guid.NewGuid().ToString()).Options);
        var clock = new FixedClock(new DateTimeOffset(2025, 1, 1, 12, 0, 0, TimeSpan.Zero));
        return (new UserService(db, new PasswordHasher<AppUser>(), clock), db, clock);
    }

    [Fact]
    public async Task Passwords_are_stored_hashed_not_in_plain_text()
    {
        var (service, db, _) = Create();
        var (user, error) = await service.CreateAsync("Alice@Example.com", "Alice", "correct-horse-battery", Roles.User);

        Assert.Null(error);
        Assert.Equal("alice@example.com", user!.Email);
        var stored = await db.Users.SingleAsync();
        Assert.DoesNotContain("correct-horse-battery", stored.PasswordHash);
        Assert.Equal(PasswordVerificationResult.Success,
            new PasswordHasher<AppUser>().VerifyHashedPassword(stored, stored.PasswordHash, "correct-horse-battery"));
    }

    [Theory]
    [InlineData("not-an-email", "Name", "long-enough-pw", "User")]
    [InlineData("a@b.c", "", "long-enough-pw", "User")]
    [InlineData("a@b.c", "Name", "short", "User")]
    [InlineData("a@b.c", "Name", "long-enough-pw", "SuperAdmin")]
    public async Task Rejects_invalid_new_users(string email, string name, string password, string role)
    {
        var (service, _, _) = Create();
        var (user, error) = await service.CreateAsync(email, name, password, role);
        Assert.Null(user);
        Assert.NotNull(error);
    }

    [Fact]
    public async Task Rejects_duplicate_email_regardless_of_case()
    {
        var (service, _, _) = Create();
        await service.CreateAsync("bob@example.com", "Bob", "long-enough-pw", Roles.User);
        var (user, error) = await service.CreateAsync("BOB@example.com", "Bob 2", "long-enough-pw", Roles.User);
        Assert.Null(user);
        Assert.Contains("already exists", error);
    }

    [Fact]
    public async Task Valid_login_succeeds_and_records_last_login()
    {
        var (service, _, clock) = Create();
        await service.CreateAsync("carol@example.com", "Carol", "long-enough-pw", Roles.User);

        var result = await service.VerifyLoginAsync(" Carol@Example.com ", "long-enough-pw");

        Assert.Equal(LoginStatus.Success, result.Status);
        Assert.Equal(clock.Now.UtcDateTime, result.User!.LastLoginAtUtc);
    }

    [Fact]
    public async Task Unknown_user_and_wrong_password_return_the_same_status()
    {
        var (service, _, _) = Create();
        await service.CreateAsync("dave@example.com", "Dave", "long-enough-pw", Roles.User);

        Assert.Equal(LoginStatus.InvalidCredentials, (await service.VerifyLoginAsync("nobody@example.com", "x")).Status);
        Assert.Equal(LoginStatus.InvalidCredentials, (await service.VerifyLoginAsync("dave@example.com", "wrong")).Status);
    }

    [Fact]
    public async Task Account_locks_after_repeated_failures_and_unlocks_after_the_lockout_window()
    {
        var (service, _, clock) = Create();
        await service.CreateAsync("erin@example.com", "Erin", "long-enough-pw", Roles.User);

        for (var i = 0; i < UserService.MaxFailedAttempts - 1; i++)
            Assert.Equal(LoginStatus.InvalidCredentials, (await service.VerifyLoginAsync("erin@example.com", "wrong")).Status);
        Assert.Equal(LoginStatus.LockedOut, (await service.VerifyLoginAsync("erin@example.com", "wrong")).Status);

        // Correct password is still refused while locked out.
        Assert.Equal(LoginStatus.LockedOut, (await service.VerifyLoginAsync("erin@example.com", "long-enough-pw")).Status);

        clock.Now += UserService.LockoutDuration + TimeSpan.FromSeconds(1);
        Assert.Equal(LoginStatus.Success, (await service.VerifyLoginAsync("erin@example.com", "long-enough-pw")).Status);
    }

    [Fact]
    public async Task Inactive_accounts_cannot_sign_in()
    {
        var (service, _, _) = Create();
        var (user, _) = await service.CreateAsync("frank@example.com", "Frank", "long-enough-pw", Roles.User);
        await service.SetActiveAsync(user!, false);

        Assert.Equal(LoginStatus.Inactive, (await service.VerifyLoginAsync("frank@example.com", "long-enough-pw")).Status);
    }

    [Fact]
    public async Task Role_changes_rotate_the_security_stamp()
    {
        var (service, _, _) = Create();
        var (user, _) = await service.CreateAsync("gina@example.com", "Gina", "long-enough-pw", Roles.User);
        var before = user!.SecurityStamp;

        await service.SetRoleAsync(user, Roles.Admin);

        Assert.Equal(Roles.Admin, user.Role);
        Assert.NotEqual(before, user.SecurityStamp);
    }
}

public class BrowserEndpointTests
{
    [Theory]
    [InlineData("http://s3:4566", "http://localhost:4566", "http://localhost:4566")]
    [InlineData("http://localhost:4566", "", "http://localhost:4566")]
    [InlineData("http://localhost:4566", null, "http://localhost:4566")]
    [InlineData(null, null, "")]
    public void Prefers_public_endpoint_and_ignores_blank_values(string? serviceUrl, string? publicUrl, string expected) =>
        Assert.Equal(expected, S3FileStorageService.BrowserEndpoint(new StorageOptions { ServiceUrl = serviceUrl, PublicServiceUrl = publicUrl }));
}

public class UploadOptionsTests
{
    [Fact]
    public void Effective_extensions_fall_back_to_defaults_and_are_deduplicated()
    {
        Assert.Equal(UploadOptions.DefaultExtensions, new UploadOptions().EffectiveExtensions);
        Assert.Equal([".pdf", ".png"], new UploadOptions { AllowedExtensions = [".PDF", " .pdf", ".png", ""] }.EffectiveExtensions);
    }

    [Fact]
    public void Binding_from_configuration_does_not_duplicate_defaults()
    {
        var config = new Microsoft.Extensions.Configuration.ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?> { ["Upload:AllowedExtensions:0"] = ".pdf" }).Build();
        var options = config.GetSection("Upload").Get<UploadOptions>()!;
        Assert.Equal([".pdf"], options.EffectiveExtensions);
    }
}
