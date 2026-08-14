using System.Security.Cryptography;

namespace Crossdyne.Security.Utilities
{
    /// <summary>
    /// 
    /// </summary>
    public static class HashSizeHelper
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="hashAlgorithm"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        public static int GetHashSizeBytes(HashAlgorithmName hashAlgorithm) => hashAlgorithm switch
        {
            var h when h == HashAlgorithmName.SHA256 => 32,
            var h when h == HashAlgorithmName.SHA384 => 48,
            var h when h == HashAlgorithmName.SHA512 => 64,
            _ => throw new ArgumentException($"Unsupported hash algorithm: {hashAlgorithm.Name}", nameof(hashAlgorithm))
        };
    }
}