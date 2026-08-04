using System.Security.Cryptography;
using System.Text;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Configuration;
using Crossdyne.Security.Exceptions;
using Crossdyne.Security.Utilities;

namespace Crossdyne.Security.Srp.Client
{
    public class SrpKeyDerivationService : ISrpKeyDerivationService
    {
        /// <inheritdoc />
        public byte[] DeriveAuthHashForSrp(string identity, string password, byte[] salt, SrpGroup srpGroup, CryptoVersion version)
        {
            if (string.IsNullOrWhiteSpace(identity))
                throw new ArgumentException("Identity cannot be null or empty.", nameof(identity));

            if (string.IsNullOrWhiteSpace(password))
                throw new ArgumentException("Password cannot be null or empty.", nameof(password));

            if (salt == null)
                throw new InvalidKeyException("Salt must not be null.");

            if (salt.Length < 16)
                throw new InvalidKeyException("Salt must be at least 16 bytes.");

            var srpProfile = SrpProfileRegistry.GetProfile(srpGroup);
            var hashAlgo = srpProfile.HashAlgorithm;

            CryptoProfile profile = CryptoProfileRegistry.GetProfile(version);
            KdfOptions opts = profile.KdfOptions;
            opts.Validate();

            int hashSize = HashSizeHelper.GetHashSizeBytes(hashAlgo);

            string combinedPassword = $"{identity}:{password}";

            byte[]? masterKey = null;

            try
            {
                masterKey = Rfc2898DeriveBytes.Pbkdf2(
                    combinedPassword, 
                    salt, 
                    opts.Pbkdf2Iterations, 
                    hashAlgo, 
                    hashSize);

                byte[] emptySalt = [];

                byte[] authHash = HKDF.DeriveKey(
                    hashAlgo, 
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