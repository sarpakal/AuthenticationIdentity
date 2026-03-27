using AuthApi.Models;
using AuthApi.Services;
using Microsoft.Extensions.Options;

namespace AuthApi.Infrastructure;

/// <summary>
/// Background service that periodically runs the audit log retention cleanup.
/// Runs once at startup (after a short delay) then on the configured interval.
/// </summary>
public class AuditRetentionJob : BackgroundService
{
    private readonly IServiceScopeFactory       _scopeFactory;
    private readonly AuditRetentionOptions      _options;
    private readonly ILogger<AuditRetentionJob> _logger;

    public AuditRetentionJob(
        IServiceScopeFactory scopeFactory,
        IOptions<AuditRetentionOptions> options,
        ILogger<AuditRetentionJob> logger)
    {
        _scopeFactory = scopeFactory;
        _options      = options.Value;
        _logger       = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        // Short startup delay so the app is fully ready before first run
        await Task.Delay(TimeSpan.FromSeconds(30), ct);

        _logger.LogInformation(
            "Audit retention job scheduled — interval: every {Hours}h, default retention: {Days} days",
            _options.RunIntervalHours, _options.DefaultRetentionDays);

        while (!ct.IsCancellationRequested)
        {
            await RunOnce(ct);
            await Task.Delay(
                TimeSpan.FromHours(_options.RunIntervalHours), ct);
        }
    }

    private async Task RunOnce(CancellationToken ct)
    {
        try
        {
            // IAuditRetentionService is scoped — resolve per run
            await using var scope = _scopeFactory.CreateAsyncScope();
            var service = scope.ServiceProvider.GetRequiredService<IAuditRetentionService>();
            await service.RunAsync(ct);
        }
        catch (OperationCanceledException)
        {
            // App is shutting down — exit cleanly
        }
        catch (Exception ex)
        {
            // Log but don't crash the host — next run will try again
            _logger.LogError(ex, "Unexpected error in audit retention job");
        }
    }
}
