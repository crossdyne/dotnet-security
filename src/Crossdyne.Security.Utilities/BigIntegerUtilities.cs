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
        /// Converts <see cref="BigInteger"/> to fixed-length big-endian bytes (zero-pads if needed).
        /// </summary>
        /// <param name="value">The value to serialize.</param>
        /// <param name="length">Output length in bytes (must be positive).</param>
        /// <returns>Big-endian byte array of exactly <paramref name="length"/> bytes.</returns>
        /// <exception cref="ArgumentException">
        /// <paramref name="length"/> is less than or equal to zero,
        /// or <paramref name="value"/> requires more bytes than <paramref name="length"/>.
        /// </exception>
        public static byte[] ToFixedLengthBytes(BigInteger value, int length)
        {
            if (length <= 0) 
                throw new ArgumentException("The length must be positive.", nameof(length));

            byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);

            if (bytes.Length == length)
                return bytes;

            if (bytes.Length > length)
                throw new ArgumentException($"Value byte length ({bytes.Length}) exceeds expected length ({length}). Possible data corruption or context mismatch.", nameof(value));

            byte[] result = new byte[length];
            Buffer.BlockCopy(bytes, 0, result, length - bytes.Length, bytes.Length);
            return result;
        }

        /// <summary>
        /// Decodes a URL-safe or standard Base64 string to raw bytes (with padding fix).
        /// </summary>
        /// <param name="base64">Base64-encoded string (URL-safe or standard).</param>
        /// <returns>Decoded raw bytes.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="base64"/> is null or empty.</exception>
        /// <exception cref="FormatException"><paramref name="base64"/> is not a valid Base64 string.</exception>
        public static byte[] DecodeBase64ToBytes(string base64)
        {
            if (string.IsNullOrEmpty(base64))
                throw new ArgumentNullException(nameof(base64));

            string cleaned = base64.Replace('-', '+').Replace('_', '/');
            int mod = cleaned.Length % 4;

            if (mod != 0)
                cleaned += new string('=', 4 - mod);

            return Convert.FromBase64String(cleaned);
        }

        /// <summary>
        /// Converts a Base64-encoded value to an unsigned, big-endian <see cref="BigInteger"/>.
        /// </summary>
        /// <param name="base64">Base64-encoded bytes.</param>
        /// <returns>Unsigned <see cref="BigInteger"/>.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="base64"/> is null or empty.</exception>
        /// <exception cref="FormatException"><paramref name="base64"/> is not a valid Base64 string.</exception>
        public static BigInteger FromBase64(string base64)
        {
            byte[] bytes = DecodeBase64ToBytes(base64);
            return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
        }

        /// <summary>
        /// Hashes concatenated byte arrays and returns an unsigned, big-endian <see cref="BigInteger"/>.
        /// </summary>
        /// <param name="hashAlgorithmName">Hash algorithm to use.</param>
        /// <param name="buffers">Byte arrays to concatenate and hash.</param>
        /// <returns>Hash value as an unsigned, big-endian <see cref="BigInteger"/>.</returns>
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
        /// <param name="hashAlgorithmName">Hash algorithm to use.</param>
        /// <param name="buffers">Byte arrays to concatenate and hash.</param>
        /// <returns>Raw hash bytes.</returns>
        public static byte[] ComputeHash(HashAlgorithmName hashAlgorithmName, params byte[][] buffers)
        {
            using var incrementalHash = IncrementalHash.CreateHash(hashAlgorithmName);

            foreach (var buffer in buffers)
                incrementalHash.AppendData(buffer);

            return incrementalHash.GetHashAndReset();
        }
    }
}