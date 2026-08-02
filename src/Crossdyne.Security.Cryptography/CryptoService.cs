using System.Security.Cryptography;
using System.Text;
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
    public class CryptoService : ICryptoService
    {
        #region Encrypted

        /// <summary>
        /// Encrypts an object to a Base64 string with configurable AES-GCM options.
        /// Nonce is generated randomly.
        /// </summary>
        /// <typeparam name="T">Serializable type.</typeparam>
        /// <param name="data">Object to encrypt.</param>
        /// <param name="key">AES-256 key (32 bytes).</param>
        /// <param name="version">Crypto configuration. <c>V1</c> uses default.</param>
        /// <exception cref="ArgumentNullException">Key is null.</exception>
        /// <exception cref="InvalidKeyException">Key is not 32 bytes.</exception>
        /// <exception cref="SecurityException">Encryption failed.</exception>
        public string EncryptedData<T>(T data, byte[] key, CryptoVersion version = CryptoVersion.V1)
        {
            ArgumentNullException.ThrowIfNull(key);

            if (key.Length != SecurityConstants.KeySizeBytes)
                throw new InvalidKeyException($"Key must be {SecurityConstants.KeySizeBytes} bytes for AES-256.");

            CryptoProfile profile = CryptoProfileRegistry.GetProfile(version);
            AesGcmOptions opts = profile.AesGcmOptions;
            opts.Validate();

            byte[] plainBytes;

            if (data is byte[] bytes)
            {
                var base64 = Convert.ToBase64String(bytes);
                plainBytes = Encoding.UTF8.GetBytes($"\"{base64}\"");
            }
            else
            {
                plainBytes = JsonSerializer.SerializeToUtf8Bytes(data!);
            }

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

            var result = new byte[1 + opts.NonceSize + cipherText.Length + opts.TagSize];
            result[0] = (byte)version;

            var resultSpan = result.AsSpan(1);
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
        /// <exception cref="ArgumentException">Input is null, empty, or invalid Base64.</exception>
        /// <exception cref="ArgumentNullException">Key is null.</exception>
        /// <exception cref="InvalidKeyException">Key is not 32 bytes.</exception>
        /// <exception cref="DecryptionException">Decryption or authentication failed.</exception>
        public T? DecryptData<T>(string encryptedBase64, byte[] key)
        {
            if (string.IsNullOrEmpty(encryptedBase64)) 
                throw new ArgumentException("Encrypted data cannot be null or empty.", nameof(encryptedBase64));

            if (key == null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length != SecurityConstants.KeySizeBytes)
                throw new InvalidKeyException($"Key must be {SecurityConstants.KeySizeBytes} bytes for AES-256.");

            byte[] encryptedBytes;

            try
            {
                encryptedBytes = Convert.FromBase64String(encryptedBase64);
            }
            catch (FormatException ex)
            {
                throw new ArgumentException("Invalid Base64 format.", nameof(encryptedBase64), ex);
            }

            CryptoVersion version = (CryptoVersion)encryptedBytes[0];
            Span<byte> payload = encryptedBytes.AsSpan(1);

            CryptoProfile profile = CryptoProfileRegistry.GetProfile(version);
            AesGcmOptions opts = profile.AesGcmOptions;
            opts.Validate();

            if (payload.Length < opts.NonceSize + opts.TagSize)
                throw new DecryptionException($"Encrypted data is too short. Expected at least {SecurityConstants.AesGcmNonceSize + SecurityConstants.AesGcmTagSize} bytes, but got {encryptedBytes.Length}");

            var nonce = payload.Slice(0, opts.NonceSize);
            var tag = payload.Slice(payload.Length - opts.TagSize, opts.TagSize);
            var cipherText = payload.Slice(opts.NonceSize, payload.Length - opts.NonceSize - opts.TagSize);

            var plainBytes = new byte[cipherText.Length];

            try
            {
                using var aes = new AesGcm(key, opts.TagSize);
                aes.Decrypt(nonce, cipherText, tag, plainBytes, opts.AssociatedData ?? ReadOnlySpan<byte>.Empty);

                if (typeof(T) == typeof(byte[]))
                {
                    var jsonString = Encoding.UTF8.GetString(plainBytes);
                    var base64 = JsonSerializer.Deserialize<string>(jsonString);

                    if (base64 == null) 
                        return default;

                    var resultBytes = Convert.FromBase64String(base64);
                    return (T?)(object?)resultBytes;
                }

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