namespace AuthApi.Models;

/// <summary>
/// Internal model carrying issued token data between service and controller layers.
/// The controller maps this to the public-facing <c>TokenResponse</c> DTO.
/// </summary>
public class TokenResult
{
    public string AccessToken { get; init; } = string.Empty;
    public string RefreshToken { get; init; } = string.Empty;
    public DateTime AccessTokenExpiresAt { get; init; }
    public DateTime RefreshTokenExpiresAt { get; init; }
    public IList<string> Roles { get; init; } = [];
}
