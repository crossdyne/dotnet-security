using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Quantropic.Security.Abstractions;

namespace Quantropic.Security.Windows
{
    /// <summary>
    /// Windows-specific implementation of <see cref="ISecureTokenStorage"/>.
    /// Securely stores and retrieves access and refresh tokens using Windows DPAPI with optional entropy.
    /// Tokens are serialized to JSON, encrypted, and persisted to a user-scoped file.
    /// </summary>
    [SupportedOSPlatform("windows")]
    public class WindowSecureTokenStorage : ISecureTokenStorage
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="WindowSecureTokenStorage"/> class.
        /// </summary>
        /// <param name="folderName">The name of the subfolder within %LocalAppData% where token data will be stored.</param>
        /// <remarks>
        /// The constructor builds the full storage path by combining 
        /// <see cref="Environment.SpecialFolder.LocalApplicationData"/> with the provided <paramref name="folderName"/>,
        /// and sets the token file path to <c>token.data</c> within that folder.
        /// </remarks>
        public WindowSecureTokenStorage(string folderName)
        {
            _folderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), folderName);
            _tokenFilePath = Path.Combine(_folderPath, "token.data");
        }
        
        private readonly string _folderPath;
        private readonly string _tokenFilePath;
        private readonly SemaphoreSlim _fileLock = new (1, 1);

        /// <summary>
        /// Optional entropy value used to strengthen DPAPI encryption. 
        /// This value is application-specific and helps prevent token extraction by other applications.
        /// </summary>
        private static readonly byte[] s_entropy = Encoding.Unicode.GetBytes("JE2D6mGrmySirkDoky91pFcMKqvt22d8");

        /// <summary>
        /// Retrieves the stored access token, if available and successfully decrypted.
        /// </summary>
        /// <returns>The access token string, or <c>null</c> if not found or decryption fails.</returns>
        public async Task<string?> GetAccessTokenAsync()
        {
            var tokenData = await ReadAndDecryptTokensAsync();
            return tokenData?.AccessToken;
        }

        /// <summary>
        /// Retrieves the stored refresh token, if available and successfully decrypted.
        /// </summary>
        /// <returns>The refresh token string, or <c>null</c> if not found or decryption fails.</returns>
        public async Task<string?> GetRefreshTokenAsync()
        {
            var tokenData = await ReadAndDecryptTokensAsync();
            return tokenData?.RefreshToken;
        }

        /// <summary>
        /// Encrypts and persists the provided access and refresh tokens to secure storage.
        /// Creates the target directory if it does not exist.
        /// </summary>
        /// <param name="accessToken">The access token to store.</param>
        /// <param name="refreshToken">The refresh token to store.</param>
        /// <returns>A <see cref="Task"/> representing the asynchronous write operation.</returns>
        public async Task StoreTokensAsync(string accessToken, string refreshToken)
        {
            var tokenData = new TokenData(accessToken, refreshToken);
            string jsonString = JsonSerializer.Serialize(tokenData);
            byte[] tokenBytes = Encoding.UTF8.GetBytes(jsonString);

            byte[] encryptedBytes = ProtectedData.Protect(tokenBytes, s_entropy, DataProtectionScope.CurrentUser);

            await _fileLock.WaitAsync();

            try
            {
                Directory.CreateDirectory(_folderPath);
                await File.WriteAllBytesAsync(_tokenFilePath, encryptedBytes);
            }
            finally
            {
                _fileLock.Release();
            }
        }

        /// <summary>
        /// Deletes the encrypted token file, effectively clearing all stored tokens.
        /// </summary>
        /// <returns>A completed <see cref="Task"/>.</returns>
        public async Task ClearTokensAsync()
        {
            await _fileLock.WaitAsync();
            try
            {
                if (File.Exists(_tokenFilePath))
                {
                    File.Delete(_tokenFilePath);
                }
            }
            finally
            {
                _fileLock.Release();
            }
        }

        /// <summary>
        /// Reads the encrypted token file, decrypts it using DPAPI with entropy, and deserializes the result.
        /// </summary>
        /// <returns>A <see cref="TokenData"/> instance if successful; otherwise, <c>null</c>.</returns>
        private async Task<TokenData?> ReadAndDecryptTokensAsync()
        {
            await _fileLock.WaitAsync();

            try
            {
                if (!File.Exists(_tokenFilePath))
                    return null;

                byte[] encryptedBytes = await File.ReadAllBytesAsync(_tokenFilePath);
                byte[] decryptedBytes = ProtectedData.Unprotect(encryptedBytes, s_entropy, DataProtectionScope.CurrentUser);

                string jsonString = Encoding.UTF8.GetString(decryptedBytes);
                var tokenData = JsonSerializer.Deserialize<TokenData>(jsonString);

                return tokenData;
            }
            catch (Exception) 
            {
                return null;
            }
            finally
            {
                _fileLock.Release();
            }
        }
    }
}