using System.Numerics;
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
        public static byte[] ToModulusBytes(SrpContext ctx, BigInteger value) =>
            BigIntegerUtilities.ToFixedLengthBytes(value, ctx.ModulusSize);

        /// <summary>
        /// Serializes a <see cref="BigInteger"/> to hash-sized (32-byte) big-endian bytes.
        /// </summary>
        /// <param name="ctx">SRP context.</param>
        /// <param name="value">Value to serialize.</param>
        public static byte[] ToHashBytes(SrpContext ctx, BigInteger value) =>
            BigIntegerUtilities.ToFixedLengthBytes(value, ctx.HashSize);

        /// <summary>
        /// Hashes modulus-sized values (e.g., u = H(A, B)).
        /// </summary>
        /// <param name="ctx">SRP context.</param>
        /// <param name="values">Values to hash.</param>
        public static BigInteger HashModuli(SrpContext ctx, params BigInteger[] values) =>
            BigIntegerUtilities.Hash(ctx.HashAlgorithmName, values.Select(v => ToModulusBytes(ctx, v)).ToArray());

        /// <summary>
        /// Computes M1 = H(A || B || sessionKeyK).
        /// </summary>
        /// <param name="ctx">SRP context.</param>
        /// <param name="A">Client ephemeral public key.</param>
        /// <param name="B">Server ephemeral public key.</param>
        /// <param name="sessionKeyK">Session key bytes.</param>
        public static byte[] ComputeM1(SrpContext ctx, BigInteger A, BigInteger B, byte[] sessionKeyK) =>
        BigIntegerUtilities.ComputeHash(
            ctx.HashAlgorithmName,
            ToModulusBytes(ctx, A),
            ToModulusBytes(ctx, B),
            sessionKeyK
        );

        /// <summary>
        /// Computes M2 = H(A || M1 || sessionKeyK).
        /// </summary>
        /// <param name="ctx">SRP context.</param>
        /// <param name="A">Client ephemeral public key.</param>
        /// <param name="M1_Bytes">Client proof.</param>
        /// <param name="sessionKeyK">Session key bytes.</param>
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
        public static byte[] ComputeSessionKey(SrpContext ctx, BigInteger S)
        {
            byte[] sBytes = ToModulusBytes(ctx, S);
            return BigIntegerUtilities.ComputeHash(ctx.HashAlgorithmName, sBytes);
        }
    }
}