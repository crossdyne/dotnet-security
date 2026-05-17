using System.Numerics;
using System.Security.Cryptography;

namespace Quantropic.Security.Utilities
{    
    /// <summary>
    /// Provides utility methods for handling <see cref="BigInteger"/> operations in cryptographic contexts.
    /// </summary>
    public static class BigIntegerUtilities
    {
        /// <summary>
        /// Converts a <see cref="BigInteger"/> to a big-endian byte array of fixed length.
        /// If the value is too large, the most significant bytes are truncated.
        /// If too short, it is left-padded with zeros.
        /// </summary>
        /// <param name="value">The value to convert.</param>
        /// <param name="length">The desired output length in bytes.</param>
        /// <returns>A byte array of the specified length.</returns>
        /// <exception cref="ArgumentException">Thrown if <paramref name="length"/> is not positive.</exception>
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
        /// Parses a URL-safe Base64-encoded string into a <see cref="BigInteger"/>.
        /// Handles padding and character replacement to ensure compatibility with standard Base64 decoding.
        /// </summary>
        /// <param name="base64">The URL-safe Base64 string to parse.</param>
        /// <returns>The decoded value as a <see cref="BigInteger"/>.</returns>
        /// <exception cref="ArgumentNullException">Thrown if <paramref name="base64"/> is null or empty.</exception>
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
        /// Computes a SHA-256 hash over the concatenation of multiple byte arrays and returns the result as a <see cref="BigInteger"/>.
        /// </summary>
        /// <param name="buffers">The byte arrays to hash.</param>
        /// <returns>The hash result as an unsigned, big-endian <see cref="BigInteger"/>.</returns>
        public static BigInteger Hash(params byte[][] buffers)
        {
            using var ms = new MemoryStream();

            foreach (var buffer in buffers)
                ms.Write(buffer);
                
            byte[] hash = SHA256.HashData(ms.ToArray());

            return new BigInteger(hash, isUnsigned: true, isBigEndian: true);
        }
    }
}