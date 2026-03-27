namespace AuthApi.Models;

/// <summary>
/// Strongly-typed options for the audit log retention policy.
/// Bound from the "AuditRetention" section in appsettings.json.
/// </summary>
public class AuditRetentionOptions
{
    public const string SectionName = "AuditRetention";

    /// <summary>How often the cleanup job runs (hours).</summary>
    public int RunIntervalHours { get; init; } = 24;

    /// <summary>Default age in days before an audit log entry is deleted.</summary>
    public int DefaultRetentionDays { get; init; } = 90;

    /// <summary>
    /// Per-event-type retention overrides (days).
    /// Keys match <see cref="AuthApi.Entities.AuditEventTypes"/> constants.
    /// Missing keys fall back to <see cref="DefaultRetentionDays"/>.
    /// </summary>
    public Dictionary<string, int> RetentionOverrides { get; init; } = new();

    /// <summary>Returns the retention period for a given event type.</summary>
    public int GetRetentionDays(string eventType) =>
        RetentionOverrides.TryGetValue(eventType, out var days)
            ? days
            : DefaultRetentionDays;
}
