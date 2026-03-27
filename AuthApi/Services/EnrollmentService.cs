using System.Security.Cryptography;
using System.Text;
using AuthApi.Entities;
using AuthApi.Models;
using Microsoft.AspNetCore.Identity;

namespace AuthApi.Services;

public interface IEnrollmentService
{
    /// <summary>Find or create a user, generate and send OTP. Returns EnrollmentResult.</summary>
    Task<EnrollmentResult> RegisterAsync(string phoneNumber);

    /// <summary>Validate OTP for a phone number. Returns OtpValidationResult.</summary>
    Task<OtpValidationResult> ValidateOtpAsync(string phoneNumber, string otpCode);

    /// <summary>Issue access + refresh tokens for a verified user. Returns TokenResult.</summary>
    Task<TokenResult> IssueTokensAsync(ApplicationUser user);

    /// <summary>Resend OTP with cooldown enforcement. Returns EnrollmentResult.</summary>
    Task<EnrollmentResult> ResendOtpAsync(string phoneNumber);
}

public class EnrollmentService : IEnrollmentService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOtpService   _otp;
    private readonly ISmsService   _sms;
    private readonly ITokenService _tokens;
    private readonly ILogger<EnrollmentService> _logger;

    private const int OtpExpirySeconds  = 120;
    private const int CooldownSeconds   = 30;
    private const int MaxOtpAttempts    = 5;

    public EnrollmentService(
        UserManager<ApplicationUser> userManager,
        IOtpService otp,
        ISmsService sms,
        ITokenService tokens,
        ILogger<EnrollmentService> logger)
    {
        _userManager = userManager;
        _otp         = otp;
        _sms         = sms;
        _tokens      = tokens;
        _logger      = logger;
    }

    // ── RegisterAsync ────────────────────────────────────────────────────────
    public async Task<EnrollmentResult> RegisterAsync(string phoneNumber)
    {
        var isNewUser = false;
        var user      = await _userManager.FindByNameAsync(phoneNumber);

        if (user == null)
        {
            // First time — create the user
            user = new ApplicationUser
            {
                UserName    = phoneNumber,
                PhoneNumber = phoneNumber,
                EnrolledAt  = DateTime.UtcNow,
                IsActive    = true,
            };

            var createResult = await _userManager.CreateAsync(user);
            if (!createResult.Succeeded)
            {
                _logger.LogWarning("Failed to create user for {Phone}: {Errors}",
                    phoneNumber,
                    string.Join("; ", createResult.Errors.Select(e => e.Description)));

                return EnrollmentResult.Failed(EnrollmentFailureReason.PersistenceFailed);
            }

            await _userManager.AddToRoleAsync(user, "User");
            isNewUser = true;
        }

        if (!user.IsActive)
            return EnrollmentResult.Failed(EnrollmentFailureReason.UserInactive);

        // Generate OTP and persist
        var otpCode = _otp.Generate();
        user.OtpCode     = otpCode;
        user.OtpExpiry   = DateTime.UtcNow.AddSeconds(OtpExpirySeconds);
        user.OtpAttempts = 0;

        var updateResult = await _userManager.UpdateAsync(user);
        if (!updateResult.Succeeded)
            return EnrollmentResult.Failed(EnrollmentFailureReason.PersistenceFailed);

        // Send SMS — catch provider failures without crashing the flow
        try
        {
            await _sms.SendOtpAsync(phoneNumber, otpCode);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SMS send failed for {Phone}", phoneNumber);
            return EnrollmentResult.Failed(EnrollmentFailureReason.SmsSendFailed);
        }

        return EnrollmentResult.Ok(user.Id, isNewUser);
    }

    // ── ValidateOtpAsync ─────────────────────────────────────────────────────
    public async Task<OtpValidationResult> ValidateOtpAsync(string phoneNumber, string otpCode)
    {
        var user = await _userManager.FindByNameAsync(phoneNumber);

        if (user == null)
            return OtpValidationResult.Failed(OtpFailureReason.UserNotFound);

        if (!user.IsActive)
            return OtpValidationResult.Failed(OtpFailureReason.UserInactive);

        if (user.OtpAttempts >= MaxOtpAttempts)
            return OtpValidationResult.Failed(OtpFailureReason.TooManyAttempts);

        if (_otp.IsExpired(user.OtpExpiry))
            return OtpValidationResult.Failed(OtpFailureReason.Expired);

        // Constant-time comparison prevents timing attacks
        var valid = CryptographicOperations.FixedTimeEquals(
            Encoding.UTF8.GetBytes(user.OtpCode ?? ""),
            Encoding.UTF8.GetBytes(otpCode));

        if (!valid)
        {
            user.OtpAttempts++;
            await _userManager.UpdateAsync(user);
            return OtpValidationResult.Failed(
                OtpFailureReason.InvalidCode,
                attemptsRemaining: MaxOtpAttempts - user.OtpAttempts);
        }

        // Valid — clear OTP state and mark phone verified
        user.OtpCode         = null;
        user.OtpExpiry       = null;
        user.OtpAttempts     = 0;
        user.IsPhoneVerified = true;
        await _userManager.UpdateAsync(user);

        return OtpValidationResult.Valid();
    }

    // ── IssueTokensAsync ─────────────────────────────────────────────────────
    public async Task<TokenResult> IssueTokensAsync(ApplicationUser user)
    {
        var roles        = await _userManager.GetRolesAsync(user);
        var accessToken  = _tokens.GenerateAccessToken(user, roles);
        var refreshToken = _tokens.GenerateRefreshToken();
        var accessExpiry = DateTime.UtcNow.AddMinutes(15);
        var refreshExpiry= DateTime.UtcNow.AddDays(7);

        user.RefreshToken       = _tokens.HashToken(refreshToken);
        user.RefreshTokenExpiry = refreshExpiry;
        await _userManager.UpdateAsync(user);

        return new TokenResult
        {
            AccessToken          = accessToken,
            RefreshToken         = refreshToken,
            AccessTokenExpiresAt = accessExpiry,
            RefreshTokenExpiresAt= refreshExpiry,
            Roles                = roles,
        };
    }

    // ── ResendOtpAsync ───────────────────────────────────────────────────────
    public async Task<EnrollmentResult> ResendOtpAsync(string phoneNumber)
    {
        var user = await _userManager.FindByNameAsync(phoneNumber);

        if (user == null)
            return EnrollmentResult.Failed(EnrollmentFailureReason.InvalidPhoneNumber);

        if (!user.IsActive)
            return EnrollmentResult.Failed(EnrollmentFailureReason.UserInactive);

        // Enforce cooldown
        if (user.OtpExpiry.HasValue)
        {
            var issuedAt          = user.OtpExpiry.Value.AddSeconds(-OtpExpirySeconds);
            var secondsSinceIssue = (DateTime.UtcNow - issuedAt).TotalSeconds;

            if (secondsSinceIssue < CooldownSeconds)
            {
                return new EnrollmentResult
                {
                    Success           = false,
                    FailureReason     = EnrollmentFailureReason.Cooldown,
                    CooldownRemaining = (int)(CooldownSeconds - secondsSinceIssue),
                };
            }
        }

        // Issue fresh OTP
        var otpCode = _otp.Generate();
        user.OtpCode     = otpCode;
        user.OtpExpiry   = DateTime.UtcNow.AddSeconds(OtpExpirySeconds);
        user.OtpAttempts = 0;

        var updateResult = await _userManager.UpdateAsync(user);
        if (!updateResult.Succeeded)
            return EnrollmentResult.Failed(EnrollmentFailureReason.PersistenceFailed);

        try
        {
            await _sms.SendOtpAsync(phoneNumber, otpCode);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SMS resend failed for {Phone}", phoneNumber);
            return EnrollmentResult.Failed(EnrollmentFailureReason.SmsSendFailed);
        }

        return EnrollmentResult.Ok(user.Id, isNewUser: false);
    }
}
