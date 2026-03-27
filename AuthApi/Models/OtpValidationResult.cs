namespace AuthApi.Models;

/// <summary>
/// Structured result returned by OTP validation logic,
/// separating outcome from controller-level HTTP decisions.
/// </summary>
public class OtpValidationResult
{
    public bool IsValid { get; init; }
    public OtpFailureReason? FailureReason { get; init; }
    public int AttemptsRemaining { get; init; }

    public static OtpValidationResult Valid() =>
        new() { IsValid = true };

    public static OtpValidationResult Failed(OtpFailureReason reason, int attemptsRemaining = 0) =>
        new() { IsValid = false, FailureReason = reason, AttemptsRemaining = attemptsRemaining };
}

public enum OtpFailureReason
{
    InvalidCode,
    Expired,
    TooManyAttempts,
    UserNotFound,
    UserInactive,
}
