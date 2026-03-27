namespace AuthApi.Services;

public interface ISmsService
{
    Task SendOtpAsync(string phoneNumber, string otpCode);
}

/// <summary>
/// Stub implementation — logs OTP to console in development.
/// Replace with Twilio, AWS SNS, Vonage, or your SMS provider.
/// </summary>
public class ConsoleSmsService : ISmsService
{
    private readonly ILogger<ConsoleSmsService> _logger;

    public ConsoleSmsService(ILogger<ConsoleSmsService> logger) => _logger = logger;

    public Task SendOtpAsync(string phoneNumber, string otpCode)
    {
        // TODO: Replace with real SMS provider
        // e.g. Twilio: await _twilioClient.Messages.CreateAsync(...)
        _logger.LogWarning(
            "DEV MODE — OTP for {Phone}: {Otp} (do not log in production!)",
            phoneNumber, otpCode);

        return Task.CompletedTask;
    }
}

/* ── Twilio example (install Twilio NuGet package) ─────────────────────────

public class TwilioSmsService : ISmsService
{
    private readonly IConfiguration _config;

    public TwilioSmsService(IConfiguration config)
    {
        _config = config;
        TwilioClient.Init(
            config["Twilio:AccountSid"],
            config["Twilio:AuthToken"]);
    }

    public async Task SendOtpAsync(string phoneNumber, string otpCode)
    {
        await MessageResource.CreateAsync(
            body: $"Your verification code is: {otpCode}. Valid for 2 minutes.",
            from: new PhoneNumber(_config["Twilio:FromNumber"]),
            to:   new PhoneNumber(phoneNumber));
    }
}

─────────────────────────────────────────────────────────────────────────── */