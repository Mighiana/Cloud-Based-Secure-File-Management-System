using System.Security.Claims;
using SecureFileUploadPortal.Data;

namespace SecureFileUploadPortal.Security;

public static class FileAccessPolicy
{
    /// <summary>Users may access only files they uploaded; administrators may access every file.</summary>
    public static bool CanAccess(ClaimsPrincipal user, FileRecord file) =>
        user.IsInRole(Roles.Admin) || user.GetUserId() == file.OwnerId;
}
