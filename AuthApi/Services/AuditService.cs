using AuthApi.Data;
using AuthApi.Entities;
using AuthApi.Models;

namespace AuthApi.Services;

public interface IAuditService
{
    Task LogAsync(
        string userId,
        string eventType,
        DeviceInfo device,
        HttpContext ctx,
        bool success = true,
        string? failureReason = null);
}

public class AuditService : IAuditService
{
    private readonly AppDbContext _db;
    private readonly ILogger<AuditService> _logger;

    public AuditService(AppDbContext db, ILogger<AuditService> logger)
    {
        _db     = db;
        _logger = logger;
    }

    public async Task LogAsync(
        string userId,
        string eventType,
        DeviceInfo device,
        HttpContext ctx,
        bool success = true,
        string? failureReason = null)
    {
        try
        {
            var entry = new UserAuditLog
            {
                UserId        = userId,
                EventType     = eventType,
                Success       = success,
                FailureReason = failureReason,
                Timestamp     = DateTime.UtcNow,

                // Network
                IpAddress     = device.IpAddress,

                // HTTP
                UserAgent     = device.UserAgent,
                HttpMethod    = ctx.Request.Method,
                RequestPath   = ctx.Request.Path,
                RequestId     = ctx.TraceIdentifier,

                // Device
                DeviceId       = device.DeviceId,
                DeviceType     = device.DeviceType,
                DeviceOs       = device.DeviceOs,
                DeviceOsVersion= device.DeviceOsVersion,
                DeviceModel    = device.DeviceModel,
                AppVersion     = device.AppVersion,
                DeviceLanguage = device.DeviceLanguage,
                DeviceTimezone = device.DeviceTimezone,
                Fingerprint    = device.Fingerprint,
                SessionId      = device.SessionId,
            };

            _db.AuditLogs.Add(entry);
            await _db.SaveChangesAsync();
        }
        catch (Exception ex)
        {
            // Audit failure must never break the main flow
            _logger.LogError(ex, "Failed to write audit log for user {UserId} event {Event}",
                userId, eventType);
        }
    }
}
