using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using SecureFileUploadPortal.Data;
using SecureFileUploadPortal.Models;
using SecureFileUploadPortal.Security;
using SecureFileUploadPortal.Services;

namespace SecureFileUploadPortal.Controllers;

public class AccountController(UserService users, AuditService audit) : Controller
{
    [AllowAnonymous, HttpGet]
    public IActionResult Login(string? returnUrl = null)
    {
        if (User.Identity?.IsAuthenticated == true) return RedirectToAction("Index", "Home");
        return View(new LoginViewModel { ReturnUrl = returnUrl });
    }

    [AllowAnonymous, HttpPost, EnableRateLimiting(AuthConstants.LoginRateLimitPolicy)]
    public async Task<IActionResult> Login(LoginViewModel model, CancellationToken ct)
    {
        if (!ModelState.IsValid) return View(model);

        var result = await users.VerifyLoginAsync(model.Email, model.Password, ct);
        var email = UserService.NormalizeEmail(model.Email);

        switch (result.Status)
        {
            case LoginStatus.Success:
                var user = result.User!;
                await HttpContext.SignInAsync(AuthConstants.Scheme, ClaimsFactory.Create(user));
                await audit.LogAsync(AuditActions.LoginSucceeded, true, userId: user.Id, userEmail: user.Email, ct: ct);
                return Url.IsLocalUrl(model.ReturnUrl) ? LocalRedirect(model.ReturnUrl) : RedirectToAction("Index", "Home");

            case LoginStatus.LockedOut:
                await audit.LogAsync(AuditActions.LoginLockedOut, false, userId: result.User?.Id, userEmail: email, ct: ct);
                ModelState.AddModelError(string.Empty, "Too many failed attempts. Try again later.");
                break;

            default:
                // Same message for unknown, wrong password and inactive accounts to avoid account enumeration.
                await audit.LogAsync(AuditActions.LoginFailed, false, userId: result.User?.Id, userEmail: email,
                    details: result.Status == LoginStatus.Inactive ? "Account inactive" : null, ct: ct);
                ModelState.AddModelError(string.Empty, "Invalid e-mail or password.");
                break;
        }

        model.Password = string.Empty;
        return View(model);
    }

    [HttpPost]
    public async Task<IActionResult> Logout(CancellationToken ct)
    {
        await audit.LogAsync(AuditActions.Logout, true, ct: ct);
        await HttpContext.SignOutAsync(AuthConstants.Scheme);
        return RedirectToAction(nameof(Login));
    }

    [AllowAnonymous]
    public async Task<IActionResult> AccessDenied(string? returnUrl, CancellationToken ct)
    {
        if (User.Identity?.IsAuthenticated == true)
            await audit.LogAsync(AuditActions.AccessDenied, false, target: returnUrl, ct: ct);
        return View();
    }
}
