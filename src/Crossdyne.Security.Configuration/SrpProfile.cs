using System.Security.Cryptography;

namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// 
    /// </summary>
    public class SrpProfile
    {
        /// <summary>
        /// 
        /// </summary>
        public string Name { get; init; } = null!;
        
        /// <summary>
        /// 
        /// </summary>
        public SrpOptions Options { get; init; } = null!;
        
        /// <summary>
        /// 
        /// </summary>
        public SrpGroup Group { get; init; }

        /// <summary>
        /// 
        /// </summary>
        public HashAlgorithmName HashAlgorithm { get; init; }

        /// <summary>
        /// 
        /// </summary>
        public int SaltSize { get; init; }

        // Optional: SRP protocol version identifier for future extensibility
        // public SrpVersion Version { get; init; }
    }
}