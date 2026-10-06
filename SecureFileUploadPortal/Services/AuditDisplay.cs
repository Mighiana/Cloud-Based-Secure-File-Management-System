using System.Text.RegularExpressions;
using SecureFileUploadPortal.Data;

namespace SecureFileUploadPortal.Services;

public static partial class AuditDisplay
{
    public static string Label(string action) => SplitWords().Replace(action, " $1").Replace("Cloud Trail", "CloudTrail");

    public static string BadgeClass(AuditLog entry) => entry switch
    {
        { Succeeded: false } => "bg-danger",
        { Action: AuditActions.FileUploaded or AuditActions.FileDownloaded } => "bg-primary",
        { Action: AuditActions.FileDeleted } => "bg-warning text-dark",
        { Action: AuditActions.LoginSucceeded or AuditActions.Logout } => "bg-success",
        _ => "bg-secondary",
    };

    [GeneratedRegex("(?<=[a-z])([A-Z])")]
    private static partial Regex SplitWords();
}
