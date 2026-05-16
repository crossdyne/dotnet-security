using System.Security.Cryptography;
using System.Text.Json;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Configuration;
using Crossdyne.Security.Exceptions;

namespace Crossdyne.Security.Cryptography
{    
    /// <summary>
    /// Provides AES-GCM encryption and decryption with JSON serialization. Thread-safe.
    /// </summary>
    /// <remarks>
    /// Encrypted data format (Base64): <c>[Nonce (N bytes)][Ciphertext][Tag (T bytes)]</c>.
    /// </remarks>
    public class CryptoService : ICryptoServices
    {
        #region Encrypted

        /// <summary>
        /// Encrypts an object to a Base64 string with configurable AES-GCM options.
        /// Nonce is generated randomly.
        /// </summary>
        /// <typeparam name="T">Serializable type.</typeparam>
        /// <param name="data">Object to encrypt.</param>
        /// <param name="key">AES-256 key (32 bytes).</param>
        /// <param name="options">AES-GCM configuration. <c>null</c> uses default.</param>
        /// <exception cref="ArgumentNullException">Key is null.</exception>
        /// <exception cref="InvalidKeyException">Key is not 32 bytes.</exception>
        /// <exception cref="SecurityException">Encryption failed.</exception>
        public string EncryptedData<T>(T data, byte[] key, AesGcmOptions? options = null)
        {
            ArgumentNullException.ThrowIfNull(key);

            if (key.Length != SecurityConstants.KeySizeBytes)
                throw new InvalidKeyException($"Key must be {SecurityConstants.KeySizeBytes} bytes for AES-256.");

            var opts = options ?? AesGcmOptions.Default;
            opts.Validate();


            byte[] plainBytes = JsonSerializer.SerializeToUtf8Bytes(data);

            var nonce = new byte[opts.NonceSize];
            RandomNumberGenerator.Fill(nonce);

            var cipherText = new byte[plainBytes.Length];
            var tag = new byte[opts.TagSize];

            try
            {
                using var aes = new AesGcm(key, opts.TagSize);
                aes.Encrypt(nonce, plainBytes, cipherText, tag, opts.AssociatedData ?? ReadOnlySpan<byte>.Empty);
            }
            catch (CryptographicException ex)
            {
                throw new SecurityException("Encryption failed", ex);
            }
            finally
            {
                Array.Clear(plainBytes, 0, plainBytes.Length);
            }

            var result = new byte[opts.NonceSize + cipherText.Length + opts.TagSize];
            var resultSpan = result.AsSpan();

            nonce.CopyTo(resultSpan.Slice(0, opts.NonceSize));
            cipherText.CopyTo(resultSpan.Slice(opts.NonceSize, cipherText.Length));
            tag.CopyTo(resultSpan.Slice(opts.NonceSize + cipherText.Length, opts.TagSize));

            return Convert.ToBase64String(result);
        }
        
        #endregion

        #region Decrypt

        /// <summary>
        /// Decrypts a Base64 string to an object with configurable AES-GCM options.
        /// Performs AES-GCM decryption and JSON deserialization. Clears plaintext memory after use.
        /// </summary>
        /// <typeparam name="T">Target deserialization type.</typeparam>
        /// <param name="encryptedBase64">Base64-encoded ciphertext.</param>
        /// <param name="key">AES-256 key (32 bytes).</param>
        /// <param name="options">AES-GCM configuration. <c>null</c> uses default.</param>
        /// <exception cref="ArgumentException">Input is null, empty, or invalid Base64.</exception>
        /// <exception cref="ArgumentNullException">Key is null.</exception>
        /// <exception cref="InvalidKeyException">Key is not 32 bytes.</exception>
        /// <exception cref="DecryptionException">Decryption or authentication failed.</exception>
        public T? DecryptData<T>(string encryptedBase64, byte[] key, AesGcmOptions? options = null)
        {
            if (string.IsNullOrEmpty(encryptedBase64)) 
                throw new ArgumentException("Encrypted data cannot be null or empty.", nameof(encryptedBase64));

            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != SecurityConstants.KeySizeBytes)
                throw new InvalidKeyException($"Key must be {SecurityConstants.KeySizeBytes} bytes for AES-256.");

            var opts = options ?? AesGcmOptions.Default;

            byte[] encryptedBytes;

            try
            {
                encryptedBytes = Convert.FromBase64String(encryptedBase64);
            }
            catch (FormatException ex)
            {
                throw new ArgumentException("Invalid Base64 format.", nameof(encryptedBase64), ex);
            }

            if (encryptedBytes.Length < opts.NonceSize + opts.TagSize)
                throw new DecryptionException($"Encrypted data is too short. Expected at least {SecurityConstants.AesGcmNonceSize + SecurityConstants.AesGcmTagSize} bytes, but got {encryptedBytes.Length}");

            var nonce = encryptedBytes.AsSpan(0, opts.NonceSize);
            var tag = encryptedBytes.AsSpan(encryptedBytes.Length - opts.TagSize, opts.TagSize);
            var cipherText = encryptedBytes.AsSpan(opts.NonceSize, encryptedBytes.Length - opts.NonceSize - opts.TagSize);

            var plainBytes = new byte[cipherText.Length];

            try
            {
                using var aes = new AesGcm(key, opts.TagSize);
                aes.Decrypt(nonce, cipherText, tag, plainBytes, opts.AssociatedData ?? ReadOnlySpan<byte>.Empty);

                return JsonSerializer.Deserialize<T>(plainBytes);
            }
            catch (CryptographicException ex)
            {
                throw new DecryptionException("Decryption failed: authentication tag mismatch or corrupted data.", ex);
            }
            finally
            {
                Array.Clear(plainBytes, 0, plainBytes.Length);
            }
        }

        #endregion

        /// <summary>
        /// Generates cryptographically secure random bytes using the system CSPRNG.
        /// </summary>
        /// <param name="length">Number of bytes (default 32).</param>
        /// <exception cref="ArgumentOutOfRangeException">Length is negative.</exception>
        public byte[] GenerateRandomBytes(int length = 32)
        {
            var bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }
    }
}