namespace AuthApi.Entities;

public class UserAuditLog
{
    public long Id { get; set; }
    public string UserId { get; set; } = string.Empty;
    public ApplicationUser User { get; set; } = null!;

    // Event
    public string EventType { get; set; } = string.Empty;  // e.g. Enroll, Login, Refresh, Logout, OtpSent, OtpFailed
    public bool Success { get; set; }
    public string? FailureReason { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    // Network
    public string? IpAddress { get; set; }
    public string? IpCountry { get; set; }
    public string? IpCity { get; set; }

    // HTTP request
    public string? UserAgent { get; set; }
    public string? HttpMethod { get; set; }
    public string? RequestPath { get; set; }
    public string? RequestId { get; set; }       // correlates with logs

    // Device (from client-supplied headers)
    public string? DeviceId { get; set; }
    public string? DeviceType { get; set; }      // Mobile, Desktop, Tablet
    public string? DeviceOs { get; set; }        // iOS, Android, Windows, etc.
    public string? DeviceOsVersion { get; set; }
    public string? AppVersion { get; set; }
    public string? DeviceModel { get; set; }
    public string? DeviceLanguage { get; set; }
    public string? DeviceTimezone { get; set; }

    // Session
    public string? SessionId { get; set; }
    public string? Fingerprint { get; set; }     // browser/device fingerprint hash
}

/// <summary>Well-known event type constants to avoid magic strings.</summary>
public static class AuditEventTypes
{
    public const string Enroll        = "Enroll";
    public const string OtpSent       = "OtpSent";
    public const string OtpVerified   = "OtpVerified";
    public const string OtpFailed     = "OtpFailed";
    public const string OtpExpired    = "OtpExpired";
    public const string Login         = "Login";
    public const string TokenRefresh  = "TokenRefresh";
    public const string Logout        = "Logout";
    public const string AccountLocked = "AccountLocked";

    /// <summary>All known event types — used by the retention job.</summary>
    public static readonly IReadOnlyList<string> All =
    [
        Enroll, OtpSent, OtpVerified, OtpFailed, OtpExpired,
        Login, TokenRefresh, Logout, AccountLocked,
    ];
}
