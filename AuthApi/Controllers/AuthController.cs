using System.IdentityModel.Tokens.Jwt;
using AuthApi.Data;
using AuthApi.DTOs;
using AuthApi.Entities;
using AuthApi.Models;
using AuthApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ITokenService           _tokens;
    private readonly IAuditService           _audit;
    private readonly ITokenBlacklistService  _blacklist;
    private readonly AppDbContext            _db;

    public AuthController(
        UserManager<ApplicationUser> userManager,
        ITokenService tokens,
        IAuditService audit,
        ITokenBlacklistService blacklist,
        AppDbContext db)
    {
        _userManager = userManager;
        _tokens      = tokens;
        _audit       = audit;
        _blacklist   = blacklist;
        _db          = db;
    }

    // ── POST /api/auth/refresh ───────────────────────────────────────────────
    [HttpPost("refresh")]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> Refresh([FromBody] RefreshRequest req)
    {
        var device = DeviceInfoExtractor.Extract(HttpContext);
        var hashed = _tokens.HashToken(req.RefreshToken);

        var user = await _userManager.Users
            .FirstOrDefaultAsync(u => u.RefreshToken == hashed);

        if (user == null || user.RefreshTokenExpiry < DateTime.UtcNow)
        {
            if (user != null)
                await _audit.LogAsync(user.Id, AuditEventTypes.TokenRefresh, device, HttpContext,
                    success: false, failureReason: "Expired refresh token");

            return Unauthorized(new ErrorResponse("Invalid or expired refresh token."));
        }

        // Rotate refresh token
        var newRefresh = _tokens.GenerateRefreshToken();
        user.RefreshToken       = _tokens.HashToken(newRefresh);
        user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(7);
        await _userManager.UpdateAsync(user);

        var roles      = await _userManager.GetRolesAsync(user);
        var newAccess  = _tokens.GenerateAccessToken(user, roles);
        var expiresAt  = DateTime.UtcNow.AddMinutes(15);

        await _audit.LogAsync(user.Id, AuditEventTypes.TokenRefresh, device, HttpContext);

        return Ok(new TokenResponse(newAccess, newRefresh, expiresAt));
    }

    // ── POST /api/auth/logout ────────────────────────────────────────────────
    [HttpPost("logout")]
    [Authorize]
    [EnableRateLimiting("auth")]
    public async Task<IActionResult> Logout([FromBody] LogoutRequest req)
    {
        var device = DeviceInfoExtractor.Extract(HttpContext);

        // ── Blacklist the current access token immediately ───────────────────
        // Even though it expires in ≤15 min, this prevents reuse after logout.
        var jti = User.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
        if (jti != null)
        {
            // Parse expiry from the current token claims
            var expClaim = User.FindFirst(JwtRegisteredClaimNames.Exp)?.Value;
            var expiry   = expClaim != null
                ? DateTimeOffset.FromUnixTimeSeconds(long.Parse(expClaim)).UtcDateTime
                : DateTime.UtcNow.AddMinutes(15); // fallback

            _blacklist.Blacklist(jti, expiry);
        }

        // ── Invalidate refresh token server-side ─────────────────────────────
        var hashed = _tokens.HashToken(req.RefreshToken);
        var user   = await _userManager.Users
            .FirstOrDefaultAsync(u => u.RefreshToken == hashed);

        if (user != null)
        {
            user.RefreshToken       = null;
            user.RefreshTokenExpiry = null;
            await _userManager.UpdateAsync(user);
            await _audit.LogAsync(user.Id, AuditEventTypes.Logout, device, HttpContext);
        }

        return NoContent();
    }

    // ── GET /api/auth/audit ──────────────────────────────────────────────────
    /// <summary>
    /// Returns the calling user's own audit history with optional filters.
    /// Supports filtering by EventType, Success, date range, DeviceOs, IpAddress.
    /// </summary>
    [HttpGet("audit")]
    [Authorize]
    public async Task<IActionResult> GetAuditHistory([FromQuery] AuditQueryParams query)
    {
        var userId = _userManager.GetUserId(User);
        if (userId == null) return Unauthorized();

        var result = await QueryAuditLogs(userId, query);
        return Ok(result);
    }

    // ── GET /api/auth/audit/admin/{userId} ────────────────────────────────────
    /// <summary>Admin endpoint — query any user's audit log with full filters.</summary>
    [HttpGet("audit/admin/{userId}")]
    [Authorize(Roles = "Admin")]
    public async Task<IActionResult> GetUserAuditHistory(
        string userId,
        [FromQuery] AuditQueryParams query)
    {
        var result = await QueryAuditLogs(userId, query);
        return Ok(result);
    }

    // ── Shared audit query helper ─────────────────────────────────────────────
    private async Task<PagedResult<object>> QueryAuditLogs(string userId, AuditQueryParams q)
    {
        var pageSize = Math.Clamp(q.PageSize, 1, 200);
        var page     = Math.Max(q.Page, 1);

        var baseQuery = _db.AuditLogs
            .Where(a => a.UserId == userId);

        // Optional filters
        if (!string.IsNullOrWhiteSpace(q.EventType))
            baseQuery = baseQuery.Where(a => a.EventType == q.EventType);

        if (q.Success.HasValue)
            baseQuery = baseQuery.Where(a => a.Success == q.Success.Value);

        if (q.From.HasValue)
            baseQuery = baseQuery.Where(a => a.Timestamp >= q.From.Value);

        if (q.To.HasValue)
            baseQuery = baseQuery.Where(a => a.Timestamp <= q.To.Value);

        if (!string.IsNullOrWhiteSpace(q.DeviceOs))
            baseQuery = baseQuery.Where(a => a.DeviceOs == q.DeviceOs);

        if (!string.IsNullOrWhiteSpace(q.IpAddress))
            baseQuery = baseQuery.Where(a => a.IpAddress == q.IpAddress);

        var totalCount = await baseQuery.CountAsync();

        var items = await baseQuery
            .OrderByDescending(a => a.Timestamp)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(a => (object)new
            {
                a.EventType,
                a.Success,
                a.FailureReason,
                a.Timestamp,
                a.IpAddress,
                a.DeviceId,
                a.DeviceType,
                a.DeviceOs,
                a.DeviceOsVersion,
                a.DeviceModel,
                a.AppVersion,
                a.DeviceLanguage,
                a.DeviceTimezone,
                a.Fingerprint,
                a.SessionId,
                a.UserAgent,
                a.RequestPath,
                a.RequestId,
            })
            .ToListAsync();

        return PagedResult<object>.Create(items, page, pageSize, totalCount);
    }
}
