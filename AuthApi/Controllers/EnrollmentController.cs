using AuthApi.DTOs;
using AuthApi.Entities;
using AuthApi.Models;
using AuthApi.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class EnrollmentController : ControllerBase
{
    private readonly IEnrollmentService _enrollment;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditService _audit;

    public EnrollmentController(
        IEnrollmentService enrollment,
        UserManager<ApplicationUser> userManager,
        IAuditService audit)
    {
        _enrollment  = enrollment;
        _userManager = userManager;
        _audit       = audit;
    }

    // ── POST /api/enrollment/register ────────────────────────────────────────
    [HttpPost("register")]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> Register([FromBody] EnrollRequest req)
    {
        var device = DeviceInfoExtractor.Extract(HttpContext);
        var phone  = req.PhoneNumber.Trim();

        var result = await _enrollment.RegisterAsync(phone);

        if (!result.Success)
            return result.FailureReason switch
            {
                EnrollmentFailureReason.UserInactive      => Forbid(),
                EnrollmentFailureReason.SmsSendFailed     => StatusCode(502,
                    new ErrorResponse("Failed to send OTP. Please try again.")),
                EnrollmentFailureReason.PersistenceFailed => StatusCode(500,
                    new ErrorResponse("Registration failed. Please try again.")),
                _ => BadRequest(new ErrorResponse("Registration failed."))
            };

        await _audit.LogAsync(result.UserId!, AuditEventTypes.OtpSent, device, HttpContext);

        return Ok(new EnrollResponse(
            result.IsNewUser ? "Account created. OTP sent to your phone." : "OTP sent to your phone.",
            phone,
            OtpExpirySeconds: 120));
    }

    // ── POST /api/enrollment/resend ──────────────────────────────────────────
    [HttpPost("resend")]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> Resend([FromBody] ResendOtpRequest req)
    {
        var device = DeviceInfoExtractor.Extract(HttpContext);
        var phone  = req.PhoneNumber.Trim();

        var result = await _enrollment.ResendOtpAsync(phone);

        if (!result.Success)
            return result.FailureReason switch
            {
                EnrollmentFailureReason.Cooldown => StatusCode(429,
                    new ResendOtpResponse(
                        $"Please wait {result.CooldownRemaining} seconds before requesting a new OTP.",
                        OtpExpirySeconds: 120,
                        CooldownSeconds: result.CooldownRemaining ?? 0)),

                EnrollmentFailureReason.UserInactive       => Forbid(),
                EnrollmentFailureReason.InvalidPhoneNumber => NotFound(
                    new ErrorResponse("Phone number not registered.")),
                EnrollmentFailureReason.SmsSendFailed      => StatusCode(502,
                    new ErrorResponse("Failed to send OTP. Please try again.")),
                _ => StatusCode(500, new ErrorResponse("Unexpected error."))
            };

        await _audit.LogAsync(result.UserId!, AuditEventTypes.OtpSent, device, HttpContext);

        return Ok(new ResendOtpResponse(
            "A new OTP has been sent to your phone number.",
            OtpExpirySeconds: 120,
            CooldownSeconds: 0));
    }

    // ── POST /api/enrollment/verify ──────────────────────────────────────────
    [HttpPost("verify")]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> Verify([FromBody] VerifyOtpRequest req)
    {
        var device = DeviceInfoExtractor.Extract(HttpContext);
        var phone  = req.PhoneNumber.Trim();

        // Validate OTP — service handles all state mutations
        var otpResult = await _enrollment.ValidateOtpAsync(phone, req.OtpCode);

        if (!otpResult.IsValid)
        {
            var (eventType, failureReason) = otpResult.FailureReason switch
            {
                OtpFailureReason.Expired         => (AuditEventTypes.OtpExpired,    "OTP expired"),
                OtpFailureReason.TooManyAttempts => (AuditEventTypes.AccountLocked, "Too many attempts"),
                _                                => (AuditEventTypes.OtpFailed,     "Invalid OTP"),
            };

            var user = await _userManager.FindByNameAsync(phone);
            if (user != null)
                await _audit.LogAsync(user.Id, eventType, device, HttpContext,
                    success: false, failureReason: failureReason);

            return otpResult.FailureReason switch
            {
                OtpFailureReason.UserNotFound    => NotFound(
                    new ErrorResponse("Phone number not registered.")),
                OtpFailureReason.UserInactive    => Forbid(),
                OtpFailureReason.Expired         => BadRequest(
                    new ErrorResponse("OTP has expired. Request a new one.")),
                OtpFailureReason.TooManyAttempts => StatusCode(429,
                    new ErrorResponse("Too many attempts. Request a new OTP.")),
                OtpFailureReason.InvalidCode     => BadRequest(
                    new ErrorResponse("Invalid OTP.",
                        $"{otpResult.AttemptsRemaining} attempts remaining.")),
                _ => BadRequest(new ErrorResponse("Verification failed."))
            };
        }

        // OTP valid — load user and issue tokens
        var verifiedUser = await _userManager.FindByNameAsync(phone);
        if (verifiedUser == null) return Unauthorized();

        // IssueTokensAsync returns the full TokenResult internal model
        TokenResult tokens = await _enrollment.IssueTokensAsync(verifiedUser);

        await _audit.LogAsync(verifiedUser.Id, AuditEventTypes.OtpVerified, device, HttpContext);
        await _audit.LogAsync(verifiedUser.Id, AuditEventTypes.Login,       device, HttpContext);

        // Map TokenResult → public TokenResponse DTO
        return Ok(new TokenResponse(
            tokens.AccessToken,
            tokens.RefreshToken,
            tokens.AccessTokenExpiresAt));
    }
}
