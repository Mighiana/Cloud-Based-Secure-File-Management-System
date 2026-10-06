using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;
using SecureFileUploadPortal.Data;

namespace SecureFileUploadPortal.Security;

/// <summary>
/// Re-checks every authenticated request against the database so that deactivation,
/// role changes and deletions take effect immediately instead of when the cookie expires.
/// </summary>
public static class CookieValidator
{
    public static async Task ValidateAsync(CookieValidatePrincipalContext context)
    {
        var principal = context.Principal;
        var userId = principal?.GetUserId();
        var stamp = principal?.FindFirst(AuthConstants.SecurityStampClaim)?.Value;

        var db = context.HttpContext.RequestServices.GetRequiredService<AppDbContext>();
        var user = userId is null ? null : await db.Users.AsNoTracking().SingleOrDefaultAsync(u => u.Id == userId);

        if (user is null || !user.IsActive || user.SecurityStamp != stamp)
        {
            context.RejectPrincipal();
            await context.HttpContext.SignOutAsync(AuthConstants.Scheme);
        }
    }
}
