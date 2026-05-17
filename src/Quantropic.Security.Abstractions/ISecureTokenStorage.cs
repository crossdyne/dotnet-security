namespace Quantropic.Security.Abstractions
{
    /// <summary>
    /// Provides secure storage for authentication tokens.
    /// </summary>
    public interface ISecureTokenStorage
    {
        /// <summary>
        /// Retrieves the stored access token.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation. The task result contains the access token, or null if not found.</returns>
        Task<string?> GetAccessTokenAsync();

        /// <summary>
        /// Retrieves the stored refresh token.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation. The task result contains the refresh token, or null if not found.</returns>
        Task<string?> GetRefreshTokenAsync();

        /// <summary>
        /// Stores access and refresh tokens securely.
        /// </summary>
        /// <param name="accessToken">The access token to store.</param>
        /// <param name="refreshToken">The refresh token to store.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        Task StoreTokensAsync(string accessToken, string refreshToken);

        /// <summary>
        /// Clears all stored tokens.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation.</returns>
        Task ClearTokensAsync();
    }
}