using System.Security.Cryptography;
using System.Text.Json;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Configuration;
using Crossdyne.Security.Exceptions;

namespace Crossdyne.Security.Cryptography
{    
    /// <summary>
    /// Provides AES-GCM encryption and decryption services with JSON serialization.
    /// </summary>
    public class CryptoService : ICryptoServices
    {
        #region Encrypted

        /// <summary>
        /// Encrypts data using default security options.
        /// </summary>
        public string EncryptedData<T>(T data, byte[] key) => EncryptedData(data, key, AesGcmOptions.Default);

        /// <summary>
        /// Encrypts data with full configuration options.
        /// </summary>
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
        /// Decrypts data using default options.
        /// </summary>
        public T? DecryptData<T>(string encryptedBase64, byte[] key) => DecryptData<T>(encryptedBase64, key, AesGcmOptions.Default);

        /// <summary>
        /// Decrypts data with configuration options.
        /// </summary>
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

            return DecryptDataV0<T>(encryptedBytes, key, opts);
        }

        /// <summary>
        /// Decrypts data format version 0 (Legacy/Current).
        /// Format: [Nonce][Ciphertext][Tag]
        /// </summary>
        private T? DecryptDataV0<T>(byte[] encryptedBytes, byte[] key, AesGcmOptions options)
        {          
            var offset = 0;
            var nonce = encryptedBytes.AsSpan(offset, options.NonceSize);
            var tag = encryptedBytes.AsSpan(encryptedBytes.Length - options.TagSize, options.TagSize);
            var cipherText = encryptedBytes.AsSpan(options.NonceSize, encryptedBytes.Length - options.NonceSize - options.TagSize);

            return DecryptCore<T>(nonce, cipherText, tag, key, options);
        }

        private T? DecryptCore<T>(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> cipherText, ReadOnlySpan<byte> tag, byte[] key, AesGcmOptions opts)
        {
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
        /// Generates cryptographically secure random bytes.
        /// </summary>
        public byte[] GenerateRandomBytes(int length = 32)
        {
            var bytes = new byte[length];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }
    }
}