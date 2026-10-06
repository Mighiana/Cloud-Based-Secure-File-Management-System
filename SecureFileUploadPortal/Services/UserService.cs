using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureFileUploadPortal.Data;

namespace SecureFileUploadPortal.Services;

public enum LoginStatus { Success, InvalidCredentials, LockedOut, Inactive }

public record LoginResult(LoginStatus Status, AppUser? User = null);

/// <summary>Credential verification and user management. Passwords are hashed with ASP.NET Core's PasswordHasher (PBKDF2).</summary>
public class UserService(AppDbContext db, IPasswordHasher<AppUser> hasher, TimeProvider clock)
{
    public const int MaxFailedAttempts = 5;
    public static readonly TimeSpan LockoutDuration = TimeSpan.FromMinutes(15);
    public const int MinPasswordLength = 10;

    public static string NormalizeEmail(string email) => email.Trim().ToLowerInvariant();

    public async Task<LoginResult> VerifyLoginAsync(string email, string password, CancellationToken ct = default)
    {
        var user = await db.Users.SingleOrDefaultAsync(u => u.Email == NormalizeEmail(email), ct);
        var now = clock.GetUtcNow().UtcDateTime;

        if (user is null)
        {
            // Hash anyway so unknown e-mails take a similar time to known ones.
            hasher.HashPassword(new AppUser(), password);
            return new LoginResult(LoginStatus.InvalidCredentials);
        }

        if (user.LockoutEndUtc > now) return new LoginResult(LoginStatus.LockedOut, user);

        var verification = hasher.VerifyHashedPassword(user, user.PasswordHash, password);
        if (verification == PasswordVerificationResult.Failed)
        {
            user.FailedLoginCount++;
            if (user.FailedLoginCount >= MaxFailedAttempts)
            {
                user.LockoutEndUtc = now.Add(LockoutDuration);
                user.FailedLoginCount = 0;
                await db.SaveChangesAsync(ct);
                return new LoginResult(LoginStatus.LockedOut, user);
            }
            await db.SaveChangesAsync(ct);
            return new LoginResult(LoginStatus.InvalidCredentials, user);
        }

        if (!user.IsActive) return new LoginResult(LoginStatus.Inactive, user);

        if (verification == PasswordVerificationResult.SuccessRehashNeeded)
            user.PasswordHash = hasher.HashPassword(user, password);

        user.FailedLoginCount = 0;
        user.LockoutEndUtc = null;
        user.LastLoginAtUtc = now;
        await db.SaveChangesAsync(ct);
        return new LoginResult(LoginStatus.Success, user);
    }

    public static string? ValidatePassword(string? password) =>
        string.IsNullOrEmpty(password) || password.Length < MinPasswordLength
            ? $"Password must be at least {MinPasswordLength} characters."
            : null;

    public async Task<(AppUser? User, string? Error)> CreateAsync(string email, string displayName, string password, string role, CancellationToken ct = default)
    {
        email = NormalizeEmail(email);
        if (string.IsNullOrWhiteSpace(email) || !email.Contains('@')) return (null, "A valid e-mail address is required.");
        if (string.IsNullOrWhiteSpace(displayName)) return (null, "Display name is required.");
        if (!Roles.All.Contains(role)) return (null, "Unknown role.");
        if (ValidatePassword(password) is { } passwordError) return (null, passwordError);
        if (await db.Users.AnyAsync(u => u.Email == email, ct)) return (null, "A user with that e-mail already exists.");

        var user = new AppUser { Email = email, DisplayName = displayName.Trim(), Role = role, CreatedAtUtc = clock.GetUtcNow().UtcDateTime };
        user.PasswordHash = hasher.HashPassword(user, password);
        db.Users.Add(user);
        await db.SaveChangesAsync(ct);
        return (user, null);
    }

    public async Task SetRoleAsync(AppUser user, string role, CancellationToken ct = default)
    {
        if (!Roles.All.Contains(role)) throw new ArgumentException("Unknown role.", nameof(role));
        user.Role = role;
        user.SecurityStamp = Guid.NewGuid().ToString("N");
        await db.SaveChangesAsync(ct);
    }

    public async Task SetActiveAsync(AppUser user, bool active, CancellationToken ct = default)
    {
        user.IsActive = active;
        user.SecurityStamp = Guid.NewGuid().ToString("N");
        await db.SaveChangesAsync(ct);
    }
}
