using Crossdyne.Security.Configuration;
using Crossdyne.Security.Exceptions;

namespace Crossdyne.Security.Abstractions
{
    /// <summary>
    /// Provides AES-GCM encryption and decryption with JSON serialization. Thread-safe.
    /// </summary>
    public interface ICryptoService
    {
        /// <summary>
        /// Encrypts an object to a Base64 string.
        /// Nonce is generated randomly.
        /// </summary>
        /// <remarks>
        /// If <typeparamref name="T"/> is <c>byte[]</c>, the raw bytes are Base64-encoded 
        /// and wrapped as a JSON string before encryption.
        /// </remarks>
        /// <typeparam name="T">Serializable type.</typeparam>
        /// <param name="data">Object to encrypt.</param>
        /// <param name="key">AES-256 key (32 bytes).</param>
        /// <param name="version">Crypto configuration. <c>V1</c> uses default.</param>
        /// <returns>Base64-encoded ciphertext with embedded version, nonce and tag.</returns>
        /// <exception cref="ArgumentNullException">Key is null.</exception>
        /// <exception cref="InvalidKeyException">Key is not 32 bytes.</exception>
        /// <exception cref="SecurityException">Encryption failed.</exception>
        string EncryptData<T>(T data, byte[] key, CryptoVersion version = CryptoVersion.V1);

        /// <summary>
        /// Decrypts a Base64 string to an object.
        /// Crypto version is read automatically from the payload header.
        /// </summary>
        /// <typeparam name="T">Target deserialization type.</typeparam>
        /// <param name="encryptedBase64">Base64-encoded ciphertext.</param>
        /// <param name="key">AES-256 key (32 bytes).</param>
        /// <returns>Deserialized object, or default if payload represents null.</returns>
        /// <exception cref="ArgumentException">Input is null, empty, or invalid Base64.</exception>
        /// <exception cref="ArgumentNullException">Key is null.</exception>
        /// <exception cref="InvalidKeyException">Key is not 32 bytes.</exception>
        /// <exception cref="DecryptionException">Decryption or authentication failed.</exception>
        T? DecryptData<T>(string encryptedBase64, byte[] key);

        /// <summary>
        /// Generates cryptographically secure random bytes using the system CSPRNG.
        /// </summary>
        /// <param name="length">Number of bytes (default 32).</param>
        /// <returns>Array of random bytes.</returns>
        /// <exception cref="ArgumentOutOfRangeException">Length is negative.</exception>
        byte[] GenerateRandomBytes(int length = 32);
    }
}