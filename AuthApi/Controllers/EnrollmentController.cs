using AuthApi.DTOs;
using AuthApi.Entities;
using AuthApi.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using System.Security.Cryptography;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/[controller]")]
[EnableRateLimiting("auth")]
public class EnrollmentController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOtpService _otp;
    private readonly ISmsService _sms;
    private readonly ITokenService _tokens;
    private readonly IAuditService _audit;
    private readonly ILogger<EnrollmentController> _logger;

    public EnrollmentController(
        UserManager<ApplicationUser> userManager,
        IOtpService otp,
        ISmsService sms,
        ITokenService tokens,
        IAuditService audit,
        ILogger<EnrollmentController> logger)
    {
        _userManager = userManager;
        _otp = otp;
        _sms = sms;
        _tokens = tokens;
        _audit = audit;
        _logger = logger;
    }

    // ── POST /api/enrollment/register ────────────────────────────────────────
    /// <summary>
    /// Step 1: Submit phone number.
    /// Creates user if new, (re)sends OTP via SMS.
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] EnrollRequest req)
    {
        var device = DeviceInfoExtractor.Extract(HttpContext);
        var phone = req.PhoneNumber.Trim();

        // Find or create user
        var user = await _userManager.FindByNameAsync(phone);
        if (user == null)
        {
            user = new ApplicationUser
            {
                UserName = phone,
                PhoneNumber = phone,
                EnrolledAt = DateTime.UtcNow,
                IsActive = true,
            };

            var result = await _userManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                var errors = string.Join("; ", result.Errors.Select(e => e.Description));
                return BadRequest(new ErrorResponse("Registration failed", errors));
            }

            await _userManager.AddToRoleAsync(user, "User");
        }

        if (!user.IsActive)
            return Forbid();

        // Generate & persist OTP (plain stored temporarily — not a secret at rest)
        var otpCode = _otp.Generate();
        user.OtpCode = otpCode;
        user.OtpExpiry = DateTime.UtcNow.AddSeconds(120);
        user.OtpAttempts = 0;
        await _userManager.UpdateAsync(user);

        // Send SMS
        await _sms.SendOtpAsync(phone, otpCode);

        await _audit.LogAsync(user.Id, AuditEventTypes.OtpSent, device, HttpContext);

        return Ok(new EnrollResponse(
            "OTP sent to your phone number.",
            phone,
            OtpExpirySeconds: 120));
    }

    // ── POST /api/enrollment/verify ──────────────────────────────────────────
    /// <summary>
    /// Step 2: Verify OTP → receive JWT tokens.
    /// </summary>
    [HttpPost("verify")]
    public async Task<IActionResult> Verify([FromBody] VerifyOtpRequest req)
    {
        var device = DeviceInfoExtractor.Extract(HttpContext);
        var phone = req.PhoneNumber.Trim();

        var user = await _userManager.FindByNameAsync(phone);
        if (user == null)
            return NotFound(new ErrorResponse("Phone number not registered."));

        if (!user.IsActive)
            return Forbid();

        // Lockout after too many failed attempts
        if (user.OtpAttempts >= 5)
        {
            await _audit.LogAsync(user.Id, AuditEventTypes.AccountLocked, device, HttpContext,
                success: false, failureReason: "Too many OTP attempts");
            return StatusCode(429, new ErrorResponse("Too many attempts. Request a new OTP."));
        }

        // Check expiry
        if (_otp.IsExpired(user.OtpExpiry))
        {
            await _audit.LogAsync(user.Id, AuditEventTypes.OtpExpired, device, HttpContext,
                success: false, failureReason: "OTP expired");
            return BadRequest(new ErrorResponse("OTP has expired. Request a new one."));
        }

        // Constant-time comparison to prevent timing attacks
        var valid = CryptographicOperations.FixedTimeEquals(
            System.Text.Encoding.UTF8.GetBytes(user.OtpCode ?? ""),
            System.Text.Encoding.UTF8.GetBytes(req.OtpCode));

        if (!valid)
        {
            user.OtpAttempts++;
            await _userManager.UpdateAsync(user);

            await _audit.LogAsync(user.Id, AuditEventTypes.OtpFailed, device, HttpContext,
                success: false, failureReason: $"Invalid OTP (attempt {user.OtpAttempts})");

            return BadRequest(new ErrorResponse("Invalid OTP.",
                $"{5 - user.OtpAttempts} attempts remaining."));
        }

        // OTP valid — clear it and mark phone verified
        user.OtpCode = null;
        user.OtpExpiry = null;
        user.OtpAttempts = 0;
        user.IsPhoneVerified = true;

        // Issue tokens
        var refreshToken = _tokens.GenerateRefreshToken();
        user.RefreshToken = _tokens.HashToken(refreshToken);
        user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);
        await _userManager.UpdateAsync(user);

        var roles = await _userManager.GetRolesAsync(user);
        var accessToken = _tokens.GenerateAccessToken(user, roles);
        var expiresAt = DateTime.UtcNow.AddMinutes(15);

        await _audit.LogAsync(user.Id, AuditEventTypes.OtpVerified, device, HttpContext);
        await _audit.LogAsync(user.Id, AuditEventTypes.Login, device, HttpContext);

        return Ok(new TokenResponse(accessToken, refreshToken, expiresAt));
    }

    [HttpGet("/")]
    [ProducesResponseType(typeof(string), StatusCodes.Status200OK)]
    public IActionResult Index()
    {
        return Ok("AuthApi is running.");
    }

}