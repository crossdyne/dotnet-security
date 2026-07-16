using Crossdyne.Security.Configuration;

namespace Crossdyne.Security.Abstractions
{
    /// <summary>
    /// Provides AES-GCM encryption and decryption with JSON serialization. Thread-safe.
    /// </summary>
    public interface ICryptoServices
    {
        /// <summary>
        /// Encrypts an object to a Base64 string with configurable AES-GCM options.
        /// Nonce is generated randomly.
        /// </summary>
        /// <typeparam name="T">Serializable type.</typeparam>
        /// <param name="data">Object to encrypt.</param>
        /// <param name="key">AES-256 key (32 bytes).</param>
        /// <param name="version">Crypto configuration. <c>V1</c> uses default.</param>
        public string EncryptedData<T>(T data, byte[] key, CryptoVersion version = CryptoVersion.V1);

        /// <summary>
        /// Decrypts a Base64 string to an object with configurable AES-GCM options.
        /// </summary>
        /// <typeparam name="T">Target deserialization type.</typeparam>
        /// <param name="encryptedBase64">Base64-encoded ciphertext.</param>
        /// <param name="key">AES-256 key (32 bytes).</param>
        T? DecryptData<T>(string encryptedBase64, byte[] key);

        /// <summary>
        /// Generates cryptographically secure random bytes using the system CSPRNG.
        /// </summary>
        /// <param name="length">Number of bytes (default 32).</param>
        byte[] GenerateRandomBytes(int length = 32);
    }
}