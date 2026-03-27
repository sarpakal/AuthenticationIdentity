namespace AuthApi.Models;

/// <summary>
/// Filter parameters accepted by audit log query endpoints.
/// All fields are optional — omitting them returns unfiltered results.
/// </summary>
public class AuditQueryParams
{
    /// <summary>Filter to a specific event type (e.g. "Login", "OtpFailed").</summary>
    public string? EventType { get; init; }

    /// <summary>Filter to only successful or only failed events.</summary>
    public bool? Success { get; init; }

    /// <summary>Return events after this UTC timestamp.</summary>
    public DateTime? From { get; init; }

    /// <summary>Return events before this UTC timestamp.</summary>
    public DateTime? To { get; init; }

    /// <summary>Filter by device OS (e.g. "iOS", "Android").</summary>
    public string? DeviceOs { get; init; }

    /// <summary>Filter by IP address.</summary>
    public string? IpAddress { get; init; }

    /// <summary>Page number (1-based).</summary>
    public int Page { get; init; } = 1;

    /// <summary>Page size — clamped to 1–200 server-side.</summary>
    public int PageSize { get; init; } = 20;
}
