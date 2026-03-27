using System.Security.Cryptography;

namespace AuthApi.Services;

public interface IOtpService
{
    string Generate();
    bool IsExpired(DateTime? expiry);
}

public class OtpService : IOtpService
{
    private readonly IConfiguration _config;

    public OtpService(IConfiguration config) => _config = config;

    public int ExpirySeconds =>
        _config.GetValue<int>("Otp:ExpirySeconds", 120);

    public int MaxAttempts =>
        _config.GetValue<int>("Otp:MaxAttempts", 5);

    /// <summary>Cryptographically random 6-digit OTP.</summary>
    public string Generate()
    {
        // Uniform distribution across 000000–999999
        var value = RandomNumberGenerator.GetInt32(0, 1_000_000);
        return value.ToString("D6");
    }

    public bool IsExpired(DateTime? expiry) =>
        expiry == null || expiry < DateTime.UtcNow;
}