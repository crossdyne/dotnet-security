using System.Numerics;
using System.Security.Cryptography;
using Crossdyne.Security.Configuration;

namespace Crossdyne.Security.Abstractions
{
    /// <summary>
    /// 
    /// </summary>
    public readonly record struct SrpContext
    {
        /// <summary>
        /// 
        /// </summary>
        public BigInteger N {get; init; }

        /// <summary>
        /// 
        /// </summary>
        public BigInteger G {get; init; }

        /// <summary>
        /// 
        /// </summary>
        public BigInteger K {get; init; }

        /// <summary>
        /// 
        /// </summary>
        public int ModulusSize {get; init; }

        /// <summary>
        /// 
        /// </summary>
        public HashAlgorithmName HashAlgorithmName {get; init; }

        /// <summary>
        /// 
        /// </summary>
        public int HashSize {get; init; }
        
        /// <summary>
        /// 
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