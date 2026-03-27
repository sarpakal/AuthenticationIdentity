using Microsoft.AspNetCore.Identity;

namespace AuthApi.Entities;

public class ApplicationUser : IdentityUser
{
    // Phone-based enrollment
    public string PhoneNumber { get; set; } = string.Empty;
    public bool IsPhoneVerified { get; set; } = false;
    public string? OtpCode { get; set; }
    public DateTime? OtpExpiry { get; set; }
    public int OtpAttempts { get; set; } = 0;

    // JWT refresh token
    public string? RefreshToken { get; set; }
    public DateTime? RefreshTokenExpiry { get; set; }

    // Enrollment metadata
    public DateTime EnrolledAt { get; set; } = DateTime.UtcNow;
    public bool IsActive { get; set; } = true;

    // Navigation
    public ICollection<UserAuditLog> AuditLogs { get; set; } = new List<UserAuditLog>();
}
