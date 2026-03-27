using AuthApi.Data;
using AuthApi.DTOs;
using AuthApi.Entities;
using AuthApi.Models;
using AuthApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = "Admin")]
public class AdminController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditService           _audit;
    private readonly IAuditRetentionService  _retention;
    private readonly AuditRetentionOptions   _retentionOptions;
    private readonly AppDbContext            _db;

    public AdminController(
        UserManager<ApplicationUser> userManager,
        IAuditService audit,
        IAuditRetentionService retention,
        IOptions<AuditRetentionOptions> retentionOptions,
        AppDbContext db)
    {
        _userManager      = userManager;
        _audit            = audit;
        _retention        = retention;
        _retentionOptions = retentionOptions.Value;
        _db               = db;
    }

    // ── GET /api/admin/users ─────────────────────────────────────────────────
    /// <summary>
    /// Paginated list of all users with optional filters.
    /// </summary>
    [HttpGet("users")]
    public async Task<IActionResult> GetUsers(
        [FromQuery] string? phone      = null,
        [FromQuery] bool?   isActive   = null,
        [FromQuery] int     page       = 1,
        [FromQuery] int     pageSize   = 20)
    {
        pageSize = Math.Clamp(pageSize, 1, 100);
        page     = Math.Max(page, 1);

        var query = _userManager.Users.AsQueryable();

        if (!string.IsNullOrWhiteSpace(phone))
            query = query.Where(u => u.PhoneNumber.Contains(phone));

        if (isActive.HasValue)
            query = query.Where(u => u.IsActive == isActive.Value);

        var totalCount = await query.CountAsync();

        var users = await query
            .OrderByDescending(u => u.EnrolledAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        // Fetch last login per user from audit logs
        var userIds    = users.Select(u => u.Id).ToList();
        var lastLogins = await _db.AuditLogs
            .Where(a => userIds.Contains(a.UserId) && a.EventType == AuditEventTypes.Login)
            .GroupBy(a => a.UserId)
            .Select(g => new { UserId = g.Key, LastLogin = g.Max(a => a.Timestamp) })
            .ToDictionaryAsync(x => x.UserId, x => x.LastLogin);

        var summaries = new List<AdminUserSummary>();
        foreach (var u in users)
        {
            var roles = await _userManager.GetRolesAsync(u);
            summaries.Add(new AdminUserSummary(
                u.Id,
                u.PhoneNumber,
                u.IsPhoneVerified,
                u.IsActive,
                u.EnrolledAt,
                roles,
                lastLogins.TryGetValue(u.Id, out var last) ? last : null));
        }

        return Ok(PagedResult<AdminUserSummary>.Create(summaries, page, pageSize, totalCount));
    }

    // ── GET /api/admin/users/{id} ────────────────────────────────────────────
    /// <summary>Full detail for a single user including audit summary.</summary>
    [HttpGet("users/{id}")]
    public async Task<IActionResult> GetUser(string id)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();

        var roles = await _userManager.GetRolesAsync(user);

        var auditSummary = await _db.AuditLogs
            .Where(a => a.UserId == id)
            .GroupBy(a => 1)
            .Select(g => new
            {
                TotalEvents      = g.Count(),
                FailedOtpAttempts = g.Count(a => a.EventType == AuditEventTypes.OtpFailed),
                LastLoginAt      = g
                    .Where(a => a.EventType == AuditEventTypes.Login)
                    .Max(a => (DateTime?)a.Timestamp),
            })
            .FirstOrDefaultAsync();

        return Ok(new AdminUserDetail(
            user.Id,
            user.PhoneNumber,
            user.IsPhoneVerified,
            user.IsActive,
            user.EnrolledAt,
            roles,
            auditSummary?.LastLoginAt,
            auditSummary?.TotalEvents    ?? 0,
            auditSummary?.FailedOtpAttempts ?? 0));
    }

    // ── PUT /api/admin/users/{id}/active ─────────────────────────────────────
    /// <summary>Activate or deactivate a user account.</summary>
    [HttpPut("users/{id}/active")]
    public async Task<IActionResult> SetActive(string id, [FromBody] SetActiveRequest req)
    {
        var device = DeviceInfoExtractor.Extract(HttpContext);
        var user   = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();

        user.IsActive = req.IsActive;

        // Revoke all sessions when deactivating
        if (!req.IsActive)
        {
            user.RefreshToken       = null;
            user.RefreshTokenExpiry = null;
        }

        await _userManager.UpdateAsync(user);

        var adminId = _userManager.GetUserId(User)!;
        await _audit.LogAsync(adminId,
            req.IsActive ? "AdminActivatedUser" : "AdminDeactivatedUser",
            device, HttpContext);

        return Ok(new { user.Id, user.IsActive });
    }

    // ── POST /api/admin/users/{id}/roles ─────────────────────────────────────
    /// <summary>Assign a role to a user.</summary>
    [HttpPost("users/{id}/roles")]
    public async Task<IActionResult> AssignRole(string id, [FromBody] AssignRoleRequest req)
    {
        var device = DeviceInfoExtractor.Extract(HttpContext);
        var user   = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();

        if (await _userManager.IsInRoleAsync(user, req.Role))
            return Conflict(new { Error = $"User already has role '{req.Role}'." });

        var result = await _userManager.AddToRoleAsync(user, req.Role);
        if (!result.Succeeded)
            return BadRequest(new { Error = string.Join("; ", result.Errors.Select(e => e.Description)) });

        var adminId = _userManager.GetUserId(User)!;
        await _audit.LogAsync(adminId, "AdminAssignedRole", device, HttpContext);

        var roles = await _userManager.GetRolesAsync(user);
        return Ok(new { user.Id, Roles = roles });
    }

    // ── DELETE /api/admin/users/{id}/roles ────────────────────────────────────
    /// <summary>Remove a role from a user.</summary>
    [HttpDelete("users/{id}/roles")]
    public async Task<IActionResult> RemoveRole(string id, [FromBody] RemoveRoleRequest req)
    {
        var device = DeviceInfoExtractor.Extract(HttpContext);
        var user   = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();

        if (!await _userManager.IsInRoleAsync(user, req.Role))
            return Conflict(new { Error = $"User does not have role '{req.Role}'." });

        var result = await _userManager.RemoveFromRoleAsync(user, req.Role);
        if (!result.Succeeded)
            return BadRequest(new { Error = string.Join("; ", result.Errors.Select(e => e.Description)) });

        var adminId = _userManager.GetUserId(User)!;
        await _audit.LogAsync(adminId, "AdminRemovedRole", device, HttpContext);

        var roles = await _userManager.GetRolesAsync(user);
        return Ok(new { user.Id, Roles = roles });
    }

    // ── GET /api/admin/users/{id}/audit ──────────────────────────────────────
    /// <summary>Full paginated audit log for any user.</summary>
    [HttpGet("users/{id}/audit")]
    public async Task<IActionResult> GetUserAudit(
        string id,
        [FromQuery] AuditQueryParams query)
    {
        var user = await _userManager.FindByIdAsync(id);
        if (user == null) return NotFound();

        var pageSize = Math.Clamp(query.PageSize, 1, 200);
        var page     = Math.Max(query.Page, 1);

        var baseQuery = _db.AuditLogs.Where(a => a.UserId == id);

        if (!string.IsNullOrWhiteSpace(query.EventType))
            baseQuery = baseQuery.Where(a => a.EventType == query.EventType);

        if (query.Success.HasValue)
            baseQuery = baseQuery.Where(a => a.Success == query.Success.Value);

        if (query.From.HasValue)
            baseQuery = baseQuery.Where(a => a.Timestamp >= query.From.Value);

        if (query.To.HasValue)
            baseQuery = baseQuery.Where(a => a.Timestamp <= query.To.Value);

        if (!string.IsNullOrWhiteSpace(query.DeviceOs))
            baseQuery = baseQuery.Where(a => a.DeviceOs == query.DeviceOs);

        if (!string.IsNullOrWhiteSpace(query.IpAddress))
            baseQuery = baseQuery.Where(a => a.IpAddress == query.IpAddress);

        var totalCount = await baseQuery.CountAsync();
        var items      = await baseQuery
            .OrderByDescending(a => a.Timestamp)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        return Ok(PagedResult<UserAuditLog>.Create(items, page, pageSize, totalCount));
    }

    // ── GET /api/admin/stats ──────────────────────────────────────────────────
    /// <summary>High-level platform statistics for the admin dashboard.</summary>
    [HttpGet("stats")]
    public async Task<IActionResult> GetStats()
    {
        var totalUsers  = await _userManager.Users.CountAsync();
        var activeUsers = await _userManager.Users.CountAsync(u => u.IsActive);
        var verifiedUsers = await _userManager.Users.CountAsync(u => u.IsPhoneVerified);

        var since24h = DateTime.UtcNow.AddHours(-24);
        var logins24h = await _db.AuditLogs
            .CountAsync(a => a.EventType == AuditEventTypes.Login && a.Timestamp >= since24h);

        var failedOtps24h = await _db.AuditLogs
            .CountAsync(a => a.EventType == AuditEventTypes.OtpFailed && a.Timestamp >= since24h);

        var newUsers24h = await _userManager.Users
            .CountAsync(u => u.EnrolledAt >= since24h);

        return Ok(new
        {
            TotalUsers    = totalUsers,
            ActiveUsers   = activeUsers,
            VerifiedUsers = verifiedUsers,
            Last24Hours   = new
            {
                NewEnrollments  = newUsers24h,
                Logins          = logins24h,
                FailedOtpAttempts = failedOtps24h,
            }
        });
    }

    // ── GET /api/admin/audit/retention ────────────────────────────────────────
    /// <summary>
    /// Returns the current retention policy and a dry-run count of rows
    /// eligible for deletion if the job ran right now.
    /// </summary>
    [HttpGet("audit/retention")]
    public async Task<IActionResult> GetRetentionPolicy()
    {
        var now     = DateTime.UtcNow;
        var preview = new Dictionary<string, object>();

        foreach (var eventType in AuditEventTypes.All)
        {
            var days   = _retentionOptions.GetRetentionDays(eventType);
            var cutoff = now.AddDays(-days);
            var count  = await _db.AuditLogs
                .CountAsync(a => a.EventType == eventType && a.Timestamp < cutoff);

            preview[eventType] = new { RetentionDays = days, EligibleForDeletion = count };
        }

        var knownTypes    = AuditEventTypes.All.ToArray();
        var defaultCutoff = now.AddDays(-_retentionOptions.DefaultRetentionDays);
        var otherCount    = await _db.AuditLogs
            .CountAsync(a => !knownTypes.Contains(a.EventType) && a.Timestamp < defaultCutoff);

        return Ok(new
        {
            RunIntervalHours     = _retentionOptions.RunIntervalHours,
            DefaultRetentionDays = _retentionOptions.DefaultRetentionDays,
            PolicyByEventType    = preview,
            OtherEventTypes      = new
            {
                RetentionDays       = _retentionOptions.DefaultRetentionDays,
                EligibleForDeletion = otherCount,
            },
        });
    }

    // ── POST /api/admin/audit/retention/run ───────────────────────────────────
    /// <summary>
    /// Manually triggers the audit log cleanup immediately.
    /// Returns a full breakdown of what was deleted.
    /// </summary>
    [HttpPost("audit/retention/run")]
    public async Task<IActionResult> RunRetention(CancellationToken ct)
    {
        var device  = DeviceInfoExtractor.Extract(HttpContext);
        var adminId = _userManager.GetUserId(User)!;

        await _audit.LogAsync(adminId, "AdminTriggeredRetention", device, HttpContext);

        var result = await _retention.RunAsync(ct);

        return result.Success
            ? Ok(result)
            : StatusCode(500, new { result.RanAt, result.Duration, result.ErrorMessage });
    }
}
