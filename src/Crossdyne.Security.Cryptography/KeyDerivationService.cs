using System.Security.Cryptography;
using System.Text;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Configuration;
using Crossdyne.Security.Exceptions;

namespace Crossdyne.Security.Cryptography
{
    /// <summary>
    /// Provides key derivation services using PBKDF2 and HKDF.
    /// </summary>
    public class KeyDerivationService: IKeyDerivationService
    {
        /// <summary>
        /// Derives keys from password using default options.
        /// </summary>
        public (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string identity, string password, byte[] salt) => DeriveKeysFromPassword(identity, password, salt, pbkdf2Iterations: null);

        /// <summary>
        /// Derives keys from password with custom iterations.
        /// </summary>
        public (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string identity, string password, byte[] salt, int? pbkdf2Iterations = null)
        {
            var options = new KdfOptions();

            if (pbkdf2Iterations.HasValue)
                options.Pbkdf2Iterations = pbkdf2Iterations.Value;

            return DeriveKeysFromPassword(identity, password, salt, options);
        }

        /// <summary>
        /// Derives keys from password with full configuration.
        /// </summary>
        public (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string identity, string password, byte[] salt, KdfOptions? options = null)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            if (salt == null)
                throw new InvalidKeyException($"Salt must be not null.");
                
            var opts = options ?? KdfOptions.Default;
            opts.Validate();
            
            string normalizedIdentity = identity.Trim().ToLowerInvariant();
            string combinedPassword = $"{normalizedIdentity}:{password}";
            byte[] masterKey = [];

            try
            {
                masterKey = Rfc2898DeriveBytes.Pbkdf2(combinedPassword, salt, opts.Pbkdf2Iterations, opts.HashAlgorithm, SecurityConstants.KeySizeBytes);
                byte[] emptySalt = []; 
                byte[] kek = HKDF.DeriveKey(opts.HashAlgorithm, masterKey, SecurityConstants.KeySizeBytes, emptySalt, Encoding.UTF8.GetBytes("AES-GCM-KEK-v1"));
                byte[] authBytes = HKDF.DeriveKey(opts.HashAlgorithm, masterKey, SecurityConstants.KeySizeBytes, emptySalt, Encoding.UTF8.GetBytes("SERVER-AUTH-HASH-v1"));

                string authHashString = Convert.ToBase64String(authBytes);
                Array.Clear(authBytes, 0, authBytes.Length);

                return (kek, authHashString);
            }
            catch (Exception ex) when (!(ex is ArgumentException || ex is InvalidKeyException || ex is SecurityException))
            {
                throw new SecurityException("Key derivation failed due to an internal error.", ex);
            }
            finally
            {
                if (masterKey.Length > 0)
                    Array.Clear(masterKey, 0, masterKey.Length);
            }
        }

        /// <summary>
        /// Derives keys specifically for the SRP protocol, ensuring the AuthHash length
        /// matches the SRP hash algorithm (SHA-256/384/512).
        /// </summary>
        public byte[] DeriveAuthHashForSrp(string identity, string password, byte[] salt, HashAlgorithmName srpHashAlgorithm,  KdfOptions? options = null)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));
            if (salt == null)
                throw new InvalidKeyException("Salt must not be null.");

            var opts = options ?? KdfOptions.Default;
            opts.Validate();

            int srpHashSize = srpHashAlgorithm switch
            {
                var h when h == HashAlgorithmName.SHA256 => 32,
                var h when h == HashAlgorithmName.SHA384 => 48,
                var h when h == HashAlgorithmName.SHA512 => 64,
                _ => throw new ArgumentException($"Unsupported hash algorithm for SRP: {srpHashAlgorithm.Name}", nameof(srpHashAlgorithm))
            };

            string normalizedIdentity = identity.Trim().ToLowerInvariant();
            string combinedPassword = $"{normalizedIdentity}:{password}";

            byte[] masterKey = new byte[SecurityConstants.KeySizeBytes];
            byte[] authHash = new byte[srpHashSize];

            try
            {
                masterKey = Rfc2898DeriveBytes.Pbkdf2(
                    combinedPassword, 
                    salt, 
                    opts.Pbkdf2Iterations, 
                    srpHashAlgorithm, 
                    SecurityConstants.KeySizeBytes);

                byte[] emptySalt = [];

                authHash = HKDF.DeriveKey(
                    srpHashAlgorithm, 
                    masterKey, 
                    srpHashSize, 
                    emptySalt, 
                    Encoding.UTF8.GetBytes("SRP-AUTH-HASH-v1"));

                byte[] result = new byte[authHash.Length];
                Buffer.BlockCopy(authHash, 0, result, 0, authHash.Length);
                return result;
            }
            catch (Exception ex) when (!(ex is ArgumentException || ex is InvalidKeyException || ex is SecurityException))
            {
                throw new SecurityException("SRP key derivation failed due to an internal error.", ex);
            }
            finally
            {
                if (masterKey.Length > 0) Array.Clear(masterKey, 0, masterKey.Length);
                if (authHash.Length > 0) Array.Clear(authHash, 0, authHash.Length);
            }
        }
    }
}