using System.Numerics;
using System.Security.Cryptography;

namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// Immutable configuration for SRP-6a. Parameters aligned with RFC 5054.
    /// </summary>
    /// <remarks>
    /// Use init-only properties to construct. Compute <c>k</c> via <see cref="ComputeK"/>.
    /// </remarks>
    public class SrpOptions
    {
        /// <summary>Diffie-Hellman group. Default <see cref="SrpGroup.Rfc5054_3072"/> (g=5).</summary>
        public SrpGroup Group { get; init; } = SrpGroup.Rfc5054_3072;

        /// <summary>Hash algorithm for SRP computations. Default SHA256.</summary>
        public HashAlgorithmName HashAlgorithmName { get; init; } = HashAlgorithmName.SHA256;

        /// <summary>Salt size in bytes. Default 32. Use a secure random generator.</summary>
        public int SaltSize { get; init; } = 32;

        /// <summary>Prime modulus N for the selected group.</summary>
        public BigInteger N => SrpGroupParams.GetN(Group);

        /// <summary>Generator g for the selected group (2, 5, or 19).</summary>
        public BigInteger  G => SrpGroupParams.GetG(Group);

        /// <summary>Byte length of N (ceil(bitLength / 8)).</summary>
        public int ModulusSize => (int)((N.GetBitLength() + 7) / 8);

        /// <summary>
        /// Computes the multiplier parameter k = H(PAD(N) || PAD(g)) (RFC 5054, 2.5.3).
        /// Thread-safe.
        /// </summary>
        public BigInteger ComputeK()
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName);
            byte[] nBytes = ToFixedLengthBytes(N, ModulusSize);
            byte[] gBytes = ToFixedLengthBytes(G, ModulusSize);

            hash.AppendData(nBytes);
            hash.AppendData(gBytes);
            var kBytes = hash.GetHashAndReset();

            return new BigInteger(kBytes, isUnsigned: true, isBigEndian: true);
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];

            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);

            return result;
        }

        /// <summary>
        /// Converts BigInteger to fixed-length big-endian bytes.
        /// </summary>
        /// <remarks>
        /// Intentionally duplicated from BigIntegerUtilities to avoid cross-layer 
        /// dependency (Configuration => Utilities). Keep in sync manually.
        /// </remarks>
        private static byte[] ToFixedLengthBytes(BigInteger value, int length)
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
    }
}