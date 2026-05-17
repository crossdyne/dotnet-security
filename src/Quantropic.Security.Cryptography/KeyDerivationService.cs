using System.Security.Cryptography;
using System.Text;
using Quantropic.Security.Abstractions;
using Quantropic.Security.Configuration;
using Quantropic.Security.Exceptions;

namespace Quantropic.Security.Cryptography
{
    /// <summary>
    /// Provides key derivation services using PBKDF2 and HKDF.
    /// </summary>
    public class KeyDerivationService: IKeyDerivationService
    {
        /// <summary>
        /// Derives keys from password using default options.
        /// </summary>
        public (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string login, string password, byte[] salt) => DeriveKeysFromPassword(login, password, salt, pbkdf2Iterations: null);

        /// <summary>
        /// Derives keys from password with custom iterations.
        /// </summary>
        public (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string login, string password, byte[] salt, int? pbkdf2Iterations = null)
        {
            var options = new CryptoOptions();

            if (pbkdf2Iterations.HasValue)
                options.Pbkdf2Iterations = pbkdf2Iterations.Value;

            return DeriveKeysFromPassword(login, password, salt, options);
        }

        /// <summary>
        /// Derives keys from password with full configuration.
        /// </summary>
        public (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string login, string password, byte[] salt, CryptoOptions? options = null)
        {
            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            if (salt == null)
                throw new InvalidKeyException($"Salt must be not null.");
                
            var opts = options ?? CryptoOptions.Default;
            opts.Validate();
            
            string normalizedLogin = login.Trim().ToLowerInvariant();
            string combinedPassword = $"{normalizedLogin}:{password}";
            byte[] masterKey = [];

            try
            {
                masterKey = Rfc2898DeriveBytes.Pbkdf2(combinedPassword, salt, opts.Pbkdf2Iterations, HashAlgorithmName.SHA256, SecurityConstants.KeySizeBytes);
                byte[] emptySalt = []; 
                byte[] kek = HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, SecurityConstants.KeySizeBytes, emptySalt, Encoding.UTF8.GetBytes("AES-GCM-KEK-v1"));
                byte[] authBytes = HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, SecurityConstants.KeySizeBytes, emptySalt, Encoding.UTF8.GetBytes("SERVER-AUTH-HASH-v1"));

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
    }
}