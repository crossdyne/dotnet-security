using System.Security.Cryptography;

namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// 
    /// </summary>
    public class SrpProfileRegistry
    {
        /// <summary>
        /// 
        /// </summary>
        public static SrpProfile GetProfile(SrpGroup group)
        {
            var hashAlgo = group switch
            {
                SrpGroup.Rfc5054_1024 => HashAlgorithmName.SHA256,
                SrpGroup.Rfc5054_2048 => HashAlgorithmName.SHA256,
                SrpGroup.Rfc5054_3072 => HashAlgorithmName.SHA256,
                SrpGroup.Rfc5054_4096 => HashAlgorithmName.SHA384,
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

        /// <summary>
        /// 
        /// </summary>
        public static SrpProfile Default => GetProfile(SrpGroup.Rfc5054_3072);
    }
}