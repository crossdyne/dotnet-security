using System.Security.Cryptography;

namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// Immutable named SRP-6a profile aggregating <see cref="SrpOptions"/> with denormalized properties.
    /// </summary>
    public class SrpProfile
    {
        /// <summary>Unique profile name.</summary>
        public string Name { get; init; } = null!;
        
        /// <summary>SRP cryptographic options (authoritative parameter source).</summary>
        public SrpOptions Options { get; init; } = null!;

        /// <summary>Diffie-Hellman group (mirrors <see cref="SrpOptions.Group"/>).</summary>
        public SrpGroup Group { get; init; }

        /// <summary>Hash algorithm (mirrors <see cref="SrpOptions.HashAlgorithmName"/>).</summary>
        public HashAlgorithmName HashAlgorithm { get; init; }

        /// <summary>Salt size in bytes (mirrors <see cref="SrpOptions.SaltSize"/>).</summary>
        public int SaltSize { get; init; }
    }
}