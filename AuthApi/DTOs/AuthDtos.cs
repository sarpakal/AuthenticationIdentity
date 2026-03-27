using System.ComponentModel.DataAnnotations;

namespace AuthApi.DTOs;

// ── Enrollment ─────────────────────────────────────────────────────────────

public record EnrollRequest(
    [Required, Phone] string PhoneNumber
);

public record EnrollResponse(
    string Message,
    string PhoneNumber,
    int OtpExpirySeconds
);

// ── OTP Verification ────────────────────────────────────────────────────────

public record VerifyOtpRequest(
    [Required, Phone] string PhoneNumber,
    [Required, Length(6, 6)] string OtpCode
);

// ── Token ───────────────────────────────────────────────────────────────────

public record TokenResponse(
    string AccessToken,
    string RefreshToken,
    DateTime ExpiresAt
);

// ── Refresh ──────────────────────────────────────────────────────────────────

public record RefreshRequest(
    [Required] string RefreshToken
);

// ── Logout ───────────────────────────────────────────────────────────────────

public record LogoutRequest(
    [Required] string RefreshToken
);

// ── Shared error response ─────────────────────────────────────────────────

public record ErrorResponse(string Error, string? Detail = null);