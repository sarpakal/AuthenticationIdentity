using AuthApi.Data;
using AuthApi.DTOs;
using AuthApi.Entities;
using AuthApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace AuthApi.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
public class UserController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IAuditService _audit;
    private readonly AppDbContext  _db;

    public UserController(
        UserManager<ApplicationUser> userManager,
        IAuditService audit,
        AppDbContext db)
    {
        _userManager = userManager;
        _audit       = audit;
        _db          = db;
    }

    // ── GET /api/user/me ─────────────────────────────────────────────────────
    /// <summary>Returns the calling user's own profile.</summary>
    [HttpGet("me")]
    public async Task<IActionResult> GetMe()
    {
        var user = await _userManager.GetUserAsync(User);
        if (user == null) return Unauthorized();

        var roles = await _userManager.GetRolesAsync(user);

        return Ok(new UserProfileResponse(
            user.Id,
            user.PhoneNumber,
            user.IsPhoneVerified,
            user.IsActive,
            user.EnrolledAt,
            roles));
    }

    // ── GET /api/user/me/sessions ────────────────────────────────────────────
    /// <summary>
    /// Returns the calling user's recent login sessions derived from audit logs.
    /// </summary>
    [HttpGet("me/sessions")]
    public async Task<IActionResult> GetMySessions()
    {
        var userId = _userManager.GetUserId(User);
        if (userId == null) return Unauthorized();

        var sessions = await _db.AuditLogs
            .Where(a => a.UserId == userId &&
                        (a.EventType == AuditEventTypes.Login ||
                         a.EventType == AuditEventTypes.Logout ||
                         a.EventType == AuditEventTypes.TokenRefresh))
            .OrderByDescending(a => a.Timestamp)
            .Take(20)
            .Select(a => new
            {
                a.EventType,
                a.Timestamp,
                a.IpAddress,
                a.DeviceType,
                a.DeviceOs,
                a.DeviceModel,
                a.AppVersion,
                a.SessionId,
            })
            .ToListAsync();

        return Ok(sessions);
    }

    // ── DELETE /api/user/me ──────────────────────────────────────────────────
    /// <summary>
    /// Soft-deletes the calling user's account by deactivating it.
    /// Does not permanently remove data (preserves audit trail).
    /// </summary>
    [HttpDelete("me")]
    public async Task<IActionResult> DeactivateMe()
    {
        var device = DeviceInfoExtractor.Extract(HttpContext);
        var user   = await _userManager.GetUserAsync(User);
        if (user == null) return Unauthorized();

        user.IsActive       = false;
        user.RefreshToken   = null;   // invalidate all sessions
        user.RefreshTokenExpiry = null;
        await _userManager.UpdateAsync(user);

        await _audit.LogAsync(user.Id, "AccountDeactivated", device, HttpContext);

        return NoContent();
    }
}
