using Quantropic.Security.Configuration;

namespace Quantropic.Security.Abstractions
{
    /// <summary>
    /// Provides cryptographic services for data encryption and decryption.
    /// </summary>
    public interface ICryptoServices
    {
        /// <summary>
        /// Encrypts data using the provided key with default PBKDF2 iterations.
        /// </summary>
        /// <typeparam name="T">The type of data to encrypt.</typeparam>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <returns>Base64-encoded encrypted data.</returns>
        string EncryptedData<T>(T data, byte[] key);

        /// <summary>
        /// Encrypts data using the provided key with specified PBKDF2 iterations.
        /// </summary>
        /// <typeparam name="T">The type of data to encrypt.</typeparam>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="pbkdf2Iterations">The number of PBKDF2 iterations. If null, uses default value.</param>
        /// <returns>Base64-encoded encrypted data.</returns>
        public string EncryptedData<T>(T data, byte[] key, int? pbkdf2Iterations = null);

        /// <summary>
        /// Encrypts data using the provided key with custom crypto options.
        /// </summary>
        /// <typeparam name="T">The type of data to encrypt.</typeparam>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="key">The encryption key.</param>
        /// <param name="options">Optional crypto configuration options.</param>
        /// <returns>Base64-encoded encrypted data.</returns>
        public string EncryptedData<T>(T data, byte[] key, CryptoOptions? options = null);

        /// <summary>
        /// Decrypts data using the provided key with default options.
        /// </summary>
        /// <typeparam name="T">The type of data to decrypt.</typeparam>
        /// <param name="encryptedBase64">The Base64-encoded encrypted data.</param>
        /// <param name="key">The decryption key.</param>
        /// <returns>The decrypted data, or default if decryption fails.</returns>
        T? DecryptData<T>(string encryptedBase64, byte[] key);

        /// <summary>
        /// Decrypts data using the provided key with custom crypto options.
        /// </summary>
        /// <typeparam name="T">The type of data to decrypt.</typeparam>
        /// <param name="encryptedBase64">The Base64-encoded encrypted data.</param>
        /// <param name="key">The decryption key.</param>
        /// <param name="options">Optional crypto configuration options.</param>
        /// <returns>The decrypted data, or default if decryption fails.</returns>
        T? DecryptData<T>(string encryptedBase64, byte[] key, CryptoOptions? options = null);

        /// <summary>
        /// Generates cryptographically secure random bytes.
        /// </summary>
        /// <param name="length">The number of random bytes to generate. Default is 32.</param>
        /// <returns>A byte array containing cryptographically secure random bytes.</returns>
        byte[] GenerateRandomBytes(int length = 32);
    }
}