using System.Security.Cryptography;
using System.Text;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Configuration;
using Crossdyne.Security.Exceptions;
using Crossdyne.Security.Utilities;

namespace Crossdyne.Security.Cryptography
{
    /// <inheritdoc />
    /// <remarks>
    /// Implementation clears sensitive buffers via <see cref="CryptographicOperations.ZeroMemory"/>.
    /// </remarks>
    public class KeyDerivationService : IKeyDerivationService
    {
        /// <inheritdoc />
        /// <remarks>
        /// Combines identity and password as <c>identity:password</c> before PBKDF2.
        /// </remarks>
        public (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string identity, string password, byte[] salt, CryptoVersion version)
        {
            if (string.IsNullOrWhiteSpace(identity))
                throw new ArgumentException("Identity cannot be null or empty.", nameof(identity));

            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            if (salt == null)
                throw new InvalidKeyException($"Salt must be not null.");

            if (salt.Length < 16)
                throw new InvalidKeyException("Salt must be at least 16 bytes.");

            CryptoProfile profile = CryptoProfileRegistry.GetProfile(version);
            KdfOptions opts = profile.KdfOptions;
            opts.Validate();

            string combinedPassword = $"{identity}:{password}";

            byte[]? masterKey = null;

            try
            {
                int hashSize = HashSizeHelper.GetHashSizeBytes(opts.HashAlgorithm);
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
    }
}