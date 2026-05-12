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
    }
}