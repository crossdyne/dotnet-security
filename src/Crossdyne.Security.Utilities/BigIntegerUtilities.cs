using System.Numerics;
using System.Security.Cryptography;

namespace Crossdyne.Security.Utilities
{    
    /// <summary>
    /// Utility methods for <see cref="BigInteger"/> in cryptographic contexts.
    /// </summary>
    public static class BigIntegerUtilities
    {
        /// <summary>
        /// Converts <see cref="BigInteger"/> to fixed-length big-endian bytes (truncates/pads).
        /// </summary>
        /// <param name="length">Output length in bytes (must be positive).</param>
        /// <param name="value">.</param>
        /// <exception cref="ArgumentException">Length &lt;= 0.</exception>
        public static byte[] ToFixedLengthBytes(BigInteger value, int length)
        {
            if (length <= 0) throw 
                new ArgumentException("The length must be positive.", nameof(length));

            byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);

            if (bytes.Length == length)
                return bytes;

            byte[] result = new byte[length];

            if (bytes.Length > length)
                Buffer.BlockCopy(bytes, bytes.Length - length, result, 0, length);
            else
                Buffer.BlockCopy(bytes, 0, result, length - bytes.Length, bytes.Length);

            return result;
        }

        /// <summary>
        /// Parses a URL-safe Base64 string into an unsigned, big-endian <see cref="BigInteger"/>.
        /// </summary>
        /// <exception cref="ArgumentNullException"><paramref name="base64"/> is null or empty.</exception>
        public static BigInteger FromBase64(string base64)
        {
            if (string.IsNullOrEmpty(base64))
                throw new ArgumentNullException(nameof(base64));

            string cleaned = base64.Replace('-', '+').Replace('_', '/');
            int mod = cleaned.Length % 4;

            if (mod != 0)
                cleaned += new string('=', 4 - mod);

            byte[] bytes = Convert.FromBase64String(cleaned);

            return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        }

        /// <summary>
        /// Hashes concatenated byte arrays and returns an unsigned, big-endian <see cref="BigInteger"/>.
        /// </summary>
        /// <param name="hashAlgorithmName">Hash algorithm.</param>
        /// <param name="buffers">Byte arrays to hash.</param>
        public static BigInteger Hash(HashAlgorithmName hashAlgorithmName, params byte[][] buffers)
        {
            using var incrementalHash = IncrementalHash.CreateHash(hashAlgorithmName);

            foreach (var buffer in buffers)
                incrementalHash.AppendData(buffer);

            byte[] hash = incrementalHash.GetHashAndReset();

            return new BigInteger(hash, isUnsigned: true, isBigEndian: true);
        }

        /// <summary>
        /// Hashes concatenated byte arrays and returns the raw hash bytes.
        /// </summary>
        public static byte[] ComputeHash(HashAlgorithmName hashAlgorithmName, params byte[][] buffers)
        {
            using var incrementalHash = IncrementalHash.CreateHash(hashAlgorithmName);

            foreach (var buffer in buffers)
                incrementalHash.AppendData(buffer);

            return incrementalHash.GetHashAndReset();
        }
    }
}