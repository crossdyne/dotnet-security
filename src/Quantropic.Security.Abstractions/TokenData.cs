namespace Quantropic.Security.Abstractions
{
    /// <summary>
    /// Represents the token pair returned after successful authentication.
    /// Contains both the short-lived access token for API authorization
    /// and the long-lived refresh token for obtaining new access tokens.
    /// </summary>
    /// <param name="AccessToken">The JWT or access token used for authorizing API requests</param>
    /// <param name="RefreshToken">The token used to obtain a new access token when the current one expires</param>
    public record TokenData(string AccessToken, string RefreshToken);
}