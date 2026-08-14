using System.Security.Cryptography;

namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// Registry of predefined <see cref="SrpProfile"/> instances. Thread-safe, returns fresh profiles.
    /// </summary>
    public class SrpProfileRegistry
    {
        /// <summary>
        /// Returns a profile for the given <paramref name="group"/>. Name = group name, salt = 32 bytes.
        /// Hash: SHA-256 (≤3072-bit) or SHA-384 (≥4096-bit).
        /// </summary>
        public static SrpProfile GetProfile(SrpGroup group)
        {
            var hashAlgo = group switch
            {
                SrpGroup.Rfc5054_1024 or 
                SrpGroup.Rfc5054_2048 or 
                SrpGroup.Rfc5054_3072 => HashAlgorithmName.SHA256,
                SrpGroup.Rfc5054_4096 or
                SrpGroup.Rfc5054_6144 or
                SrpGroup.Rfc5054_8192 => HashAlgorithmName.SHA384,
                _ => HashAlgorithmName.SHA256
            };

            return new SrpProfile
            {
                Name = group.ToString(),
                Group = group,
                HashAlgorithm = hashAlgo,
                SaltSize = 32,
                Options = new SrpOptions
                {
                    Group = group,
                    HashAlgorithmName = hashAlgo,
                    SaltSize = 32
                }
            };
        }
    }
}