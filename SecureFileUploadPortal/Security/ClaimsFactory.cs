using System.Security.Claims;
using SecureFileUploadPortal.Data;

namespace SecureFileUploadPortal.Security;

public static class ClaimsFactory
{
    public static ClaimsPrincipal Create(AppUser user)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Email, user.Email),
            new(ClaimTypes.Name, user.DisplayName),
            new(ClaimTypes.Role, user.Role),
            new(AuthConstants.SecurityStampClaim, user.SecurityStamp),
        };
        return new ClaimsPrincipal(new ClaimsIdentity(claims, AuthConstants.Scheme));
    }

    public static int? GetUserId(this ClaimsPrincipal principal) =>
        int.TryParse(principal.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null;
}
