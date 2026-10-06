using System.Text.RegularExpressions;
using SecureFileUploadPortal.Data;

namespace SecureFileUploadPortal.Services;

public static partial class AuditDisplay
{
    public static string Label(string action) => SplitWords().Replace(action, " $1").Replace("Cloud Trail", "CloudTrail");

    public static string BadgeClass(AuditLog entry) => entry switch
    {
        { Succeeded: false } => "bg-danger",
        { Action: AuditActions.FileUploadReceived or AuditActions.FileDownloaded } => "bg-primary",
        { Action: AuditActions.FileValidationApproved } => "bg-success",
        { Action: AuditActions.FileDeleted } => "bg-warning text-dark",
        { Action: AuditActions.LoginSucceeded or AuditActions.Logout } => "bg-success",
        _ => "bg-secondary",
    };

    public static string StatusBadge(FileSecurityStatus status) => status switch
    {
        FileSecurityStatus.Approved => "bg-success",
        FileSecurityStatus.Pending or FileSecurityStatus.Validating => "bg-info text-dark",
        FileSecurityStatus.Quarantined => "bg-warning text-dark",
        _ => "bg-danger",
    };

    public static string StatusIcon(FileSecurityStatus status) => status switch
    {
        FileSecurityStatus.Approved => "fa-circle-check",
        FileSecurityStatus.Pending or FileSecurityStatus.Validating => "fa-hourglass-half",
        FileSecurityStatus.Quarantined => "fa-biohazard",
        _ => "fa-circle-xmark",
    };

    [GeneratedRegex("(?<=[a-z])([A-Z])")]
    private static partial Regex SplitWords();
}
