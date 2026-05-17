using System.Numerics;
using System.Security.Cryptography;
using Crossdyne.Security.Configuration;

namespace Crossdyne.Security.Abstractions
{
    /// <summary>
    /// Immutable SRP cryptographic context: modulus, generator, multiplier k, hash algorithm, and sizes.
    /// </summary>
    public readonly record struct SrpContext
    {
        /// <summary>Prime modulus N.</summary>
        public BigInteger N {get; init; }

        /// <summary>Generator g.</summary>
        public BigInteger G {get; init; }

        /// <summary>Multiplier k = H(N || g).</summary>
        public BigInteger K {get; init; }

        /// <summary>Modulus size in bytes (ceil(bit length / 8)).</summary>
        public int ModulusSize {get; init; }

        /// <summary>Hash algorithm used for SRP computations.</summary>
        public HashAlgorithmName HashAlgorithmName {get; init; }

        /// <summary>Hash output size in bytes (e.g., 32 for SHA-256).</summary>
        public int HashSize {get; init; }
        
        /// <summary>
        /// Creates an <see cref="SrpContext"/> from <see cref="SrpOptions"/>.
        /// </summary>
        public static SrpContext FromOptions(SrpOptions options)
        {
            var hashSize = options.HashAlgorithmName switch
            {
                var hash when hash == HashAlgorithmName.SHA256 => 32,
                var hash when hash == HashAlgorithmName.SHA384 => 48,
                var hash when hash == HashAlgorithmName.SHA512 => 64,
                _ => throw new NotSupportedException()
            };
            
            return new SrpContext
            {
                N = options.N,
                G = options.G,
                K = options.ComputeK(),
                ModulusSize = options.ModulusSize,
                HashAlgorithmName = options.HashAlgorithmName,
                HashSize = hashSize
            };
        }
    }
}