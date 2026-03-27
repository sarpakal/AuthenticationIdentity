namespace AuthApi.Models;

/// <summary>
/// Structured result from the enrollment/registration step,
/// decoupling service logic from HTTP response concerns.
/// </summary>
public class EnrollmentResult
{
    public bool Success { get; init; }
    public EnrollmentFailureReason? FailureReason { get; init; }
    public string? UserId { get; init; }
    public bool IsNewUser { get; init; }

    public static EnrollmentResult Ok(string userId, bool isNewUser) =>
        new() { Success = true, UserId = userId, IsNewUser = isNewUser };

    public static EnrollmentResult Failed(EnrollmentFailureReason reason) =>
        new() { Success = false, FailureReason = reason };
}

public enum EnrollmentFailureReason
{
    InvalidPhoneNumber,
    UserInactive,
    SmsSendFailed,
    PersistenceFailed,
}
