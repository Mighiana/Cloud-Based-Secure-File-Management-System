using Amazon.S3;
using Amazon.SecurityToken;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging; // Added for ILogger
using SecureFileUploadPortal.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddControllersWithViews();

// AWS Configuration
var awsConfig = builder.Configuration.GetSection("AWS");
builder.Services.AddSingleton<IAmazonS3>(sp =>
{
    var config = new AmazonS3Config
    {
        RegionEndpoint = Amazon.RegionEndpoint.GetBySystemName(awsConfig["Region"] ?? "eu-central-1")
    };
    return new AmazonS3Client(awsConfig["AccessKey"], awsConfig["SecretKey"], config);
});

// Register S3Service with ILogger injection (Fixed)
builder.Services.AddScoped<S3Service>(sp => new S3Service(builder.Configuration, sp.GetRequiredService<ILogger<S3Service>>()));

// File size limit (50MB)
builder.Services.Configure<IISServerOptions>(options =>
{
    options.MaxRequestBodySize = 50 * 1024 * 1024; // 50MB
});

// Enforce HTTPS
builder.Services.AddHttpsRedirection(options => options.HttpsPort = 443);

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();