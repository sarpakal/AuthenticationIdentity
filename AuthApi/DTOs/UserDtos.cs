using System.ComponentModel.DataAnnotations;

namespace AuthApi.DTOs;

// ── User Profile ─────────────────────────────────────────────────────────────

public record UserProfileResponse(
    string Id,
    string PhoneNumber,
    bool IsPhoneVerified,
    bool IsActive,
    DateTime EnrolledAt,
    IList<string> Roles
);

public record UpdateProfileRequest(
    [Phone] string? PhoneNumber   // future: allow phone change with re-verification
);

// ── Admin: User List ─────────────────────────────────────────────────────────

public record AdminUserSummary(
    string Id,
    string PhoneNumber,
    bool IsPhoneVerified,
    bool IsActive,
    DateTime EnrolledAt,
    IList<string> Roles,
    DateTime? LastLoginAt
);

public record AdminUserDetail(
    string Id,
    string PhoneNumber,
    bool IsPhoneVerified,
    bool IsActive,
    DateTime EnrolledAt,
    IList<string> Roles,
    DateTime? LastLoginAt,
    int TotalAuditEvents,
    int FailedOtpAttempts
);

// ── Admin: Actions ───────────────────────────────────────────────────────────

public record SetActiveRequest(
    [Required] bool IsActive
);

public record AssignRoleRequest(
    [Required] string Role
);

public record RemoveRoleRequest(
    [Required] string Role
);
