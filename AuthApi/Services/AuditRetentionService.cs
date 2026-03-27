using AuthApi.Data;
using AuthApi.Entities;
using AuthApi.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthApi.Services;

public interface IAuditRetentionService
{
    /// <summary>
    /// Deletes audit log entries that exceed their configured retention period.
    /// Safe to call manually (admin endpoint) or from the background job.
    /// </summary>
    Task<AuditRetentionResult> RunAsync(CancellationToken ct = default);
}

public class AuditRetentionService : IAuditRetentionService
{
    private readonly IDbContextFactory<AppDbContext> _dbFactory;
    private readonly AuditRetentionOptions           _options;
    private readonly ILogger<AuditRetentionService>  _logger;

    public AuditRetentionService(
        IDbContextFactory<AppDbContext> dbFactory,
        IOptions<AuditRetentionOptions> options,
        ILogger<AuditRetentionService> logger)
    {
        _dbFactory = dbFactory;
        _options   = options.Value;
        _logger    = logger;
    }

    public async Task<AuditRetentionResult> RunAsync(CancellationToken ct = default)
    {
        var startedAt      = DateTime.UtcNow;
        var deletedByType  = new Dictionary<string, int>();
        var totalDeleted   = 0;

        _logger.LogInformation("Audit retention job started at {Time}", startedAt);

        try
        {
            // Build a distinct list of all event types that exist in the config
            // plus a catch-all pass using the default retention days.
            var eventTypes = AuditEventTypes.All
                .Union(_options.RetentionOverrides.Keys)
                .Distinct()
                .ToList();

            await using var db = await _dbFactory.CreateDbContextAsync(ct);

            // ── Per-event-type passes ────────────────────────────────────────
            // Delete in targeted batches so the query can use the EventType index.
            foreach (var eventType in eventTypes)
            {
                var cutoff  = DateTime.UtcNow.AddDays(-_options.GetRetentionDays(eventType));
                var deleted = await db.AuditLogs
                    .Where(a => a.EventType == eventType && a.Timestamp < cutoff)
                    .ExecuteDeleteAsync(ct);

                if (deleted > 0)
                {
                    deletedByType[eventType] = deleted;
                    totalDeleted += deleted;
                    _logger.LogInformation(
                        "Deleted {Count} '{EventType}' entries older than {Cutoff:yyyy-MM-dd}",
                        deleted, eventType, cutoff);
                }
            }

            // ── Default pass — catches event types not in the list above ─────
            var knownTypes  = eventTypes.ToArray();
            var defaultCutoff = DateTime.UtcNow.AddDays(-_options.DefaultRetentionDays);
            var defaultDeleted = await db.AuditLogs
                .Where(a => !knownTypes.Contains(a.EventType) && a.Timestamp < defaultCutoff)
                .ExecuteDeleteAsync(ct);

            if (defaultDeleted > 0)
            {
                deletedByType["(other)"] = defaultDeleted;
                totalDeleted += defaultDeleted;
                _logger.LogInformation(
                    "Deleted {Count} other entries older than {Cutoff:yyyy-MM-dd}",
                    defaultDeleted, defaultCutoff);
            }

            var duration = DateTime.UtcNow - startedAt;
            _logger.LogInformation(
                "Audit retention job completed. Total deleted: {Total} in {Duration}ms",
                totalDeleted, (int)duration.TotalMilliseconds);

            return new AuditRetentionResult
            {
                RanAt              = startedAt,
                Duration           = duration,
                TotalDeleted       = totalDeleted,
                DeletedByEventType = deletedByType,
                Success            = true,
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Audit retention job failed");
            return new AuditRetentionResult
            {
                RanAt        = startedAt,
                Duration     = DateTime.UtcNow - startedAt,
                TotalDeleted = totalDeleted,
                Success      = false,
                ErrorMessage = ex.Message,
            };
        }
    }
}
