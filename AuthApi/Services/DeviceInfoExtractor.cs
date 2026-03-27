using AuthApi.Models;

namespace AuthApi.Services;

public static class DeviceInfoExtractor
{
    /// <summary>
    /// Reads device context from standard + custom X-Device-* headers.
    /// Clients (mobile/web) should send these on every request.
    /// </summary>
    public static DeviceInfo Extract(HttpContext ctx)
    {
        var headers = ctx.Request.Headers;

        return new DeviceInfo
        {
            IpAddress      = GetClientIp(ctx),
            UserAgent      = headers.UserAgent.ToString(),

            // Custom device headers — agree on these with your mobile/frontend teams
            DeviceId       = headers["X-Device-Id"].FirstOrDefault(),
            DeviceType     = headers["X-Device-Type"].FirstOrDefault(),   // Mobile|Desktop|Tablet
            DeviceOs       = headers["X-Device-Os"].FirstOrDefault(),     // iOS|Android|Windows
            DeviceOsVersion= headers["X-Device-Os-Version"].FirstOrDefault(),
            DeviceModel    = headers["X-Device-Model"].FirstOrDefault(),
            AppVersion     = headers["X-App-Version"].FirstOrDefault(),
            DeviceLanguage = headers["X-Device-Language"].FirstOrDefault(),
            DeviceTimezone = headers["X-Device-Timezone"].FirstOrDefault(),
            Fingerprint    = headers["X-Fingerprint"].FirstOrDefault(),
            SessionId      = headers["X-Session-Id"].FirstOrDefault(),
        };
    }

    private static string? GetClientIp(HttpContext ctx)
    {
        // Respect reverse proxy / load balancer forwarded headers
        var forwarded = ctx.Request.Headers["X-Forwarded-For"].FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(forwarded))
            return forwarded.Split(',')[0].Trim();

        return ctx.Connection.RemoteIpAddress?.ToString();
    }
}
