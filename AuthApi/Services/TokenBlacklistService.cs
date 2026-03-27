using System.Collections.Concurrent;

namespace AuthApi.Services;

public interface ITokenBlacklistService
{
    /// <summary>Blacklist an access token JTI until its expiry time.</summary>
    void Blacklist(string jti, DateTime expiry);

    /// <summary>Returns true if the JTI has been blacklisted.</summary>
    bool IsBlacklisted(string jti);
}

/// <summary>
/// In-memory token blacklist keyed by JWT ID (jti claim).
/// Entries are automatically evicted once the token's natural expiry passes,
/// so the set stays small (only tokens that were explicitly logged out).
///
/// Production note: replace with a Redis IDistributedCache implementation
/// when running multiple API instances so the blacklist is shared across nodes.
/// </summary>
public class TokenBlacklistService : ITokenBlacklistService, IHostedService, IDisposable
{
    // jti → expiry time
    private readonly ConcurrentDictionary<string, DateTime> _blacklist = new();
    private Timer? _cleanupTimer;

    public void Blacklist(string jti, DateTime expiry) =>
        _blacklist[jti] = expiry;

    public bool IsBlacklisted(string jti) =>
        _blacklist.TryGetValue(jti, out var expiry) && expiry > DateTime.UtcNow;

    // ── IHostedService — runs cleanup every 5 minutes ────────────────────────
    public Task StartAsync(CancellationToken ct)
    {
        _cleanupTimer = new Timer(
            callback: _ => Cleanup(),
            state:    null,
            dueTime:  TimeSpan.FromMinutes(5),
            period:   TimeSpan.FromMinutes(5));

        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken ct)
    {
        _cleanupTimer?.Change(Timeout.Infinite, 0);
        return Task.CompletedTask;
    }

    private void Cleanup()
    {
        var now     = DateTime.UtcNow;
        var expired = _blacklist
            .Where(kv => kv.Value <= now)
            .Select(kv => kv.Key)
            .ToList();

        foreach (var key in expired)
            _blacklist.TryRemove(key, out _);
    }

    public void Dispose() => _cleanupTimer?.Dispose();
}
