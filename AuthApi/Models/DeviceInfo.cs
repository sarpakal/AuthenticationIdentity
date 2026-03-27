namespace AuthApi.Models;

/// <summary>
/// Device and session context extracted from inbound HTTP headers.
/// Clients should populate X-Device-* headers on every request.
/// </summary>
public class DeviceInfo
{
    public string? DeviceId { get; init; }
    public string? DeviceType { get; init; }
    public string? DeviceOs { get; init; }
    public string? DeviceOsVersion { get; init; }
    public string? DeviceModel { get; init; }
    public string? AppVersion { get; init; }
    public string? DeviceLanguage { get; init; }
    public string? DeviceTimezone { get; init; }
    public string? Fingerprint { get; init; }
    public string? SessionId { get; init; }
    public string? UserAgent { get; init; }
    public string? IpAddress { get; init; }
}
