using System.Security.Cryptography;
using System.Text;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Configuration;
using Crossdyne.Security.Exceptions;

namespace Crossdyne.Security.Cryptography
{
    /// <summary>
    /// Two-stage key derivation: PBKDF2 (master key) → HKDF (sub-keys). Thread-safe.
    /// </summary>
    /// <remarks>
    /// Derived sub-keys: KEK (AES-GCM) and AuthHash (server verification).
    /// HKDF info strings ensure key separation.
    /// Salts must be random, unique, and at least 16 bytes.
    /// Sensitive buffers are cleared after use.
    /// </remarks>
    public class KeyDerivationService: IKeyDerivationService
    {
        private static int GetHashSizeBytes(HashAlgorithmName hashAlgorithm) => hashAlgorithm switch
        {
            var h when h == HashAlgorithmName.SHA256 => 32,
            var h when h == HashAlgorithmName.SHA384 => 48,
            var h when h == HashAlgorithmName.SHA512 => 64,
            _ => throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm.Name}", nameof(hashAlgorithm))
        };

        /// <summary>
        /// Identity is hashed as-is. Caller must normalize (trim, lowercase, etc.) 
        /// before calling to ensure cross-platform consistency.
        /// </summary>
        /// <param name="identity">User identity (email, username).</param>
        /// <param name="password">User password.</param>
        /// <param name="salt">Random salt.</param>
        /// <exception cref="ArgumentException">Password is null/empty.</exception>
        /// <exception cref="InvalidKeyException">Salt is null.</exception>
        /// <exception cref="SecurityException">Derivation error.</exception>
        public (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string identity, string password, byte[] salt) => DeriveKeysFromPassword(identity, password, salt, pbkdf2Iterations: null);

        /// <summary>
        /// Derives KEK and Base64 AuthHash with optional custom PBKDF2 iterations.
        /// Identity is hashed as-is. Caller must normalize (trim, lowercase, etc.) 
        /// before calling to ensure cross-platform consistency.
        /// </summary>
        /// <param name="identity">User identity.</param>
        /// <param name="password">User password.</param>
        /// <param name="salt">Random salt.</param>
        /// <param name="pbkdf2Iterations">Iterations; null uses default.</param>
        /// <exception cref="ArgumentException">Password null/empty.</exception>
        /// <exception cref="InvalidKeyException">Salt null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Iterations too low.</exception>
        /// <exception cref="SecurityException">Derivation error.</exception>
        public (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string identity, string password, byte[] salt, int? pbkdf2Iterations = null)
        {
            var options = new KdfOptions();

            if (pbkdf2Iterations.HasValue)
                options.Pbkdf2Iterations = pbkdf2Iterations.Value;

            return DeriveKeysFromPassword(identity, password, salt, options);
        }

        /// <summary>
        /// Full KDF configuration overload.
        /// Derivation: PBKDF2(identity:password) → HKDF(KEK, AuthHash).
        /// Identity is hashed as-is. Caller must normalize (trim, lowercase, etc.) 
        /// before calling to ensure cross-platform consistency.
        /// </summary>
        /// <param name="identity"></param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="options">KDF options; null uses default.</param>
        /// <exception cref="ArgumentException">Password null/empty.</exception>
        /// <exception cref="InvalidKeyException">Salt null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Invalid options.</exception>
        /// <exception cref="SecurityException">Derivation error.</exception>
        public (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string identity, string password, byte[] salt, KdfOptions? options = null)
        {
            if (string.IsNullOrWhiteSpace(identity))
                throw new ArgumentException("Identity cannot be null or empty.", nameof(identity));

            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            if (salt == null)
                throw new InvalidKeyException($"Salt must be not null.");

            if (salt.Length < 16)
                throw new InvalidKeyException("Salt must be at least 16 bytes.");

            var opts = options ?? KdfOptions.Default;
            opts.Validate();

            string combinedPassword = $"{identity}:{password}";

            byte[]? masterKey = null;

            try
            {
                int hashSize = GetHashSizeBytes(opts.HashAlgorithm);
                masterKey = Rfc2898DeriveBytes.Pbkdf2(combinedPassword, salt, opts.Pbkdf2Iterations, opts.HashAlgorithm, hashSize);
                byte[] emptySalt = []; 
                byte[] kek = HKDF.DeriveKey(opts.HashAlgorithm, masterKey, SecurityConstants.KeySizeBytes, emptySalt, Encoding.UTF8.GetBytes("AES-GCM-KEK-v1"));
                byte[] authBytes = HKDF.DeriveKey(opts.HashAlgorithm, masterKey, SecurityConstants.KeySizeBytes, emptySalt, Encoding.UTF8.GetBytes("SERVER-AUTH-HASH-v1"));

                string authHashString = Convert.ToBase64String(authBytes);
                CryptographicOperations.ZeroMemory(authBytes);

                return (kek, authHashString);
            }
            catch (Exception ex) when (!(ex is ArgumentException || ex is InvalidKeyException || ex is SecurityException))
            {
                throw new SecurityException("Key derivation failed due to an internal error.", ex);
            }
            finally
            {
                if (masterKey is not null)
                    CryptographicOperations.ZeroMemory(masterKey);
            }
        }

        /// <summary>
        /// Derives an SRP-compatible authentication hash (output size = hash output length).
        /// Identity is hashed as-is. Caller must normalize (trim, lowercase, etc.) 
        /// before calling to ensure cross-platform consistency.
        /// <param name="identity"></param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="srpHashAlgorithm"></param>
        /// <param name="options"></param>
        /// <returns>Raw hash bytes for use as SRP verifier input (x).</returns>
        /// <exception cref="ArgumentException">Password null/empty, or unsupported hash.</exception>
        /// <exception cref="InvalidKeyException">Salt null.</exception>
        /// <exception cref="SecurityException">Derivation error.</exception>
        /// </summary>
        public byte[] DeriveAuthHashForSrp(string identity, string password, byte[] salt, HashAlgorithmName srpHashAlgorithm,  KdfOptions? options = null)
        {
            if (string.IsNullOrWhiteSpace(identity))
                throw new ArgumentException("Identity cannot be null or empty.", nameof(identity));

            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            if (salt == null)
                throw new InvalidKeyException("Salt must not be null.");

            if (salt.Length < 16)
                throw new InvalidKeyException("Salt must be at least 16 bytes.");

            var opts = options ?? KdfOptions.Default;
            opts.Validate();

            int hashSize = GetHashSizeBytes(opts.HashAlgorithm);

            string combinedPassword = $"{identity}:{password}";

            byte[]? masterKey = null;

            try
            {
                masterKey = Rfc2898DeriveBytes.Pbkdf2(
                    combinedPassword, 
                    salt, 
                    opts.Pbkdf2Iterations, 
                    srpHashAlgorithm, 
                    hashSize);

                byte[] emptySalt = [];

                byte[] authHash = HKDF.DeriveKey(
                    srpHashAlgorithm, 
                    masterKey, 
                    hashSize, 
                    emptySalt, 
                    Encoding.UTF8.GetBytes("SRP-AUTH-HASH-v1"));
    
                return authHash;
            }
            catch (Exception ex) when (ex is not ArgumentException and not InvalidKeyException and not SecurityException)
            {
                throw new SecurityException("SRP key derivation failed due to an internal error.", ex);
            }
            finally
            {
                if (masterKey is not null) 
                    CryptographicOperations.ZeroMemory(masterKey);
            }
        }
    }
}