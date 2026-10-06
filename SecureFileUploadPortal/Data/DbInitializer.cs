using Microsoft.EntityFrameworkCore;
using SecureFileUploadPortal.Services;

namespace SecureFileUploadPortal.Data;

public static class DbInitializer
{
    /// <summary>
    /// Applies migrations (if enabled) and creates the first administrator from configuration
    /// ("Seed:AdminEmail" / "Seed:AdminPassword") when the Users table is empty.
    /// </summary>
    public static async Task InitializeAsync(IServiceProvider services, IConfiguration config, ILogger logger)
    {
        using var scope = services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();

        if (config.GetValue("Database:ApplyMigrationsOnStartup", false))
            await db.Database.MigrateAsync();

        if (await db.Users.AnyAsync()) return;

        var email = config["Seed:AdminEmail"];
        var password = config["Seed:AdminPassword"];
        if (string.IsNullOrWhiteSpace(email) || string.IsNullOrWhiteSpace(password))
        {
            logger.LogWarning("No users exist and Seed:AdminEmail / Seed:AdminPassword are not set; nobody can sign in.");
            return;
        }

        var users = scope.ServiceProvider.GetRequiredService<UserService>();
        var (admin, error) = await users.CreateAsync(email, config["Seed:AdminName"] ?? "Administrator", password, Roles.Admin);
        if (admin is null) logger.LogError("Could not seed administrator: {Error}", error);
        else logger.LogInformation("Seeded initial administrator {Email}", admin.Email);
    }
}
