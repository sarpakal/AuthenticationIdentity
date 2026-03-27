namespace AuthApi.Models;

/// <summary>
/// Summary of a single audit log retention run.
/// Returned by <see cref="AuthApi.Services.IAuditRetentionService.RunAsync"/>
/// and exposed via the admin endpoint.
/// </summary>
public class AuditRetentionResult
{
    public DateTime RanAt { get; init; } = DateTime.UtcNow;
    public TimeSpan Duration { get; init; }
    public int TotalDeleted { get; init; }

    /// <summary>Breakdown of deleted rows per event type.</summary>
    public IReadOnlyDictionary<string, int> DeletedByEventType { get; init; }
        = new Dictionary<string, int>();

    public bool Success { get; init; }
    public string? ErrorMessage { get; init; }
}
