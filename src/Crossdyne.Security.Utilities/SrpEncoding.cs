using System.Numerics;
using System.Text;
using Crossdyne.Security.Abstractions;

namespace Crossdyne.Security.Utilities
{
    /// <summary>
    /// SRP-specific serialization and hashing utilities.
    /// </summary>
    public static class SrpEncoding
    {
        /// <summary>
        /// Serializes a <see cref="BigInteger"/> to modulus-sized big-endian bytes.
        /// </summary>
        /// <param name="ctx">SRP context.</param>
        /// <param name="value">Value to serialize.</param>
        /// <returns>Modulus-sized big-endian byte array.</returns>
        public static byte[] ToModulusBytes(SrpContext ctx, BigInteger value) =>
            BigIntegerUtilities.ToFixedLengthBytes(value, ctx.ModulusSize);

        /// <summary>
        /// Serializes a <see cref="BigInteger"/> to hash-sized (32-byte) big-endian bytes.
        /// </summary>
        /// <param name="ctx">SRP context.</param>
        /// <param name="value">Value to serialize.</param>
        /// <returns>Hash-sized big-endian byte array.</returns>
        public static byte[] ToHashBytes(SrpContext ctx, BigInteger value) =>
            BigIntegerUtilities.ToFixedLengthBytes(value, ctx.HashSize);

        /// <summary>
        /// Hashes modulus-sized values (e.g., u = H(A, B)).
        /// </summary>
        /// <param name="ctx">SRP context.</param>
        /// <param name="values">Values to hash.</param>
        /// <returns>Hash result as an unsigned, big-endian <see cref="BigInteger"/>.</returns>
        public static BigInteger HashModuli(SrpContext ctx, params BigInteger[] values) =>
            BigIntegerUtilities.Hash(ctx.HashAlgorithmName, values.Select(v => ToModulusBytes(ctx, v)).ToArray());

        /// <summary>
        /// Computes the client proof M1 = H( H(N) ⊕ H(g) | H(I) | s | PAD(A) | PAD(B) | K ).
        /// </summary>
        /// <remarks>
        /// Follows RFC 5054 / SRP-6a: 
        /// <list type="bullet">
        ///   <item><description>H(N) and H(g) are hashed as modulus-sized values.</description></item>
        ///   <item><description>Identity (I) is hashed as raw UTF-8 bytes.</description></item>
        ///   <item><description>A and B are padded to the modulus size before hashing.</description></item>
        ///   <item><description>K is the session key (H(S) without padding).</description></item>
        /// </list>
        /// </remarks>
        /// <param name="ctx">SRP context containing N, g, hash algorithm, and modulus size.</param>
        /// <param name="A">Client ephemeral public key.</param>
        /// <param name="B">Server ephemeral public key.</param>
        /// <param name="sessionKeyK">Session key K as raw bytes.</param>
        /// <param name="identity">User identity (login). Should already be normalized (trimmed / lowercased) by the caller.</param>
        /// <param name="salt">User-specific salt bytes.</param>
        /// <returns>The M1 proof as raw hash bytes.</returns>
        public static byte[] ComputeM1(
            SrpContext ctx, 
            BigInteger A, 
            BigInteger B, 
            byte[] sessionKeyK, 
            string identity, 
            byte[] salt)
        {
            byte[] nBytes = ToModulusBytes(ctx, ctx.N);
            byte[] gBytes = ToModulusBytes(ctx, ctx.G);
            byte[] hashN = BigIntegerUtilities.ComputeHash(ctx.HashAlgorithmName, nBytes);
            byte[] hashG = BigIntegerUtilities.ComputeHash(ctx.HashAlgorithmName, gBytes);

            byte[] xorNg = new byte[hashN.Length];
            for (int i = 0; i < hashN.Length; i++)
                xorNg[i] = (byte)(hashN[i] ^ hashG[i]);

            byte[] hashI = BigIntegerUtilities.ComputeHash(
                ctx.HashAlgorithmName, 
                Encoding.UTF8.GetBytes(identity));

            return BigIntegerUtilities.ComputeHash(
                ctx.HashAlgorithmName,
                xorNg,
                hashI,
                salt,
                ToModulusBytes(ctx, A),
                ToModulusBytes(ctx, B),
                sessionKeyK);
        }

        /// <summary>
        /// Computes M2 = H(A || M1 || sessionKeyK).
        /// </summary>
        /// <param name="ctx">SRP context.</param>
        /// <param name="A">Client ephemeral public key.</param>
        /// <param name="M1_Bytes">Client proof.</param>
        /// <param name="sessionKeyK">Session key bytes.</param>
        /// <returns>The M2 proof as raw hash bytes.</returns>
        public static byte[] ComputeM2(SrpContext ctx, BigInteger A, byte[] M1_Bytes, byte[] sessionKeyK) =>
            BigIntegerUtilities.ComputeHash(
                ctx.HashAlgorithmName,
                ToModulusBytes(ctx, A),
                M1_Bytes,
                sessionKeyK
            );

        /// <summary>
        /// Computes session key K = H(S).
        /// </summary>
        /// <param name="ctx">SRP context.</param>
        /// <param name="S">Shared secret.</param>
        /// <returns>The session key K as raw hash bytes.</returns>
        public static byte[] ComputeSessionKey(SrpContext ctx, BigInteger S)
        {
            byte[] sBytes = S.ToByteArray(isUnsigned: true, isBigEndian: true);
            return BigIntegerUtilities.ComputeHash(ctx.HashAlgorithmName, sBytes);
        }
    }
}