using System.Threading.RateLimiting;
using Amazon;
using Amazon.Runtime;
using Amazon.S3;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using SecureFileUploadPortal.Data;
using SecureFileUploadPortal.Options;
using SecureFileUploadPortal.Security;
using SecureFileUploadPortal.Services;
using SecureFileUploadPortal.Validation;

var builder = WebApplication.CreateBuilder(args);
var services = builder.Services;

// ---- Configuration ----
services.Configure<StorageOptions>(builder.Configuration.GetSection(StorageOptions.SectionName));
services.Configure<CloudTrailOptions>(builder.Configuration.GetSection(CloudTrailOptions.SectionName));
services.Configure<UploadOptions>(builder.Configuration.GetSection(UploadOptions.SectionName));
services.Configure<ValidationOptions>(builder.Configuration.GetSection(ValidationOptions.SectionName));
var validationOptions = builder.Configuration.GetSection(ValidationOptions.SectionName).Get<ValidationOptions>() ?? new ValidationOptions();
var uploadOptions = builder.Configuration.GetSection(UploadOptions.SectionName).Get<UploadOptions>() ?? new UploadOptions();

// ---- Database ----
services.AddDbContext<AppDbContext>(o =>
    o.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
        sql => sql.EnableRetryOnFailure(maxRetryCount: 5)));

// ---- AWS S3 ----
services.AddSingleton<IAmazonS3>(sp => S3ClientFactory.Create(sp.GetRequiredService<IOptions<StorageOptions>>().Value, publicEndpoint: false));
services.AddSingleton<IFileStorageService>(sp => new S3FileStorageService(
    sp.GetRequiredService<IAmazonS3>(),
    S3ClientFactory.Create(sp.GetRequiredService<IOptions<StorageOptions>>().Value, publicEndpoint: true),
    sp.GetRequiredService<IOptions<StorageOptions>>()));
services.AddSingleton<CloudTrailLogService>();

// ---- Application services ----
services.AddHttpContextAccessor();
services.AddSingleton(TimeProvider.System);
services.AddSingleton<IPasswordHasher<AppUser>, PasswordHasher<AppUser>>();
services.AddScoped<UserService>();
services.AddScoped<AuditService>();
services.AddSingleton<UploadValidator>();

// ---- Post-upload validation pipeline (scanners run in registration order; all must return Clean) ----
services.AddSingleton<ValidationSignal>();
services.AddSingleton<IFileSecurityScanner, BasicFileValidationScanner>();
if (validationOptions.ClamAv.Enabled)
    services.AddSingleton<IFileSecurityScanner, ClamAvSecurityScanner>();
services.AddScoped<FileValidationProcessor>();
if (validationOptions.RunWorker)
    services.AddHostedService<FileValidationWorker>();

// ---- Authentication & authorization ----
services.AddAuthentication(AuthConstants.Scheme)
    .AddCookie(AuthConstants.Scheme, o =>
    {
        o.LoginPath = "/Account/Login";
        o.LogoutPath = "/Account/Logout";
        o.AccessDeniedPath = "/Account/AccessDenied";
        o.Cookie.Name = "__SecurePortal";
        o.Cookie.HttpOnly = true;
        o.Cookie.SameSite = SameSiteMode.Strict;
        o.Cookie.SecurePolicy = builder.Environment.IsDevelopment() ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
        o.ExpireTimeSpan = TimeSpan.FromMinutes(30);
        o.SlidingExpiration = true;
        o.Events.OnValidatePrincipal = CookieValidator.ValidateAsync;
    });

// Every endpoint requires a signed-in user unless marked [AllowAnonymous].
services.AddAuthorizationBuilder()
    .SetFallbackPolicy(new AuthorizationPolicyBuilder().RequireAuthenticatedUser().Build());

var loginPermitLimit = builder.Configuration.GetValue("Security:LoginAttemptsPerMinute", 10);
services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.AddPolicy(AuthConstants.LoginRateLimitPolicy, ctx => RateLimitPartition.GetFixedWindowLimiter(
        ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
        _ => new FixedWindowRateLimiterOptions { PermitLimit = loginPermitLimit, Window = TimeSpan.FromMinutes(1) }));
});

services.AddControllersWithViews(o =>
{
    o.Filters.Add(new AuthorizeFilter());
    o.Filters.Add(new AutoValidateAntiforgeryTokenAttribute());
});

// ---- Upload size limits (Kestrel + multipart) ----
var bodyLimit = uploadOptions.MaxFileSizeBytes + 1024 * 1024;
builder.WebHost.ConfigureKestrel(k => k.Limits.MaxRequestBodySize = bodyLimit);
services.Configure<FormOptions>(o => o.MultipartBodyLengthLimit = bodyLimit);

services.AddHealthChecks();

// Cookie and antiforgery keys must survive restarts/scale-out, otherwise every deploy signs all users out.
var dataProtection = services.AddDataProtection().SetApplicationName("SecureFileUploadPortal");
if (builder.Configuration["DataProtection:KeysPath"] is { Length: > 0 } keysPath)
    dataProtection.PersistKeysToFileSystem(new DirectoryInfo(keysPath));

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}
app.UseStatusCodePagesWithReExecute("/Home/StatusCode", "?code={0}");

if (app.Configuration.GetValue("UseHttpsRedirection", true))
    app.UseHttpsRedirection();

app.UseSecurityHeaders();
app.UseStaticFiles();
app.UseRouting();
app.UseRateLimiter();
app.UseAuthentication();
app.UseAuthorization();

app.MapHealthChecks("/health").AllowAnonymous();
app.MapControllerRoute(name: "default", pattern: "{controller=Home}/{action=Index}/{id?}");

await DbInitializer.InitializeAsync(app.Services, app.Configuration, app.Logger);

app.Run();

public partial class Program;
