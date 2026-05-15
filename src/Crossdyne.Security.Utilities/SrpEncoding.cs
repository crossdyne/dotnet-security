using System.Numerics;
using Crossdyne.Security.Abstractions;

namespace Crossdyne.Security.Utilities
{
    /// <summary>
    /// Provides encoding and hashing utilities specific to the SRP protocol.
    /// Handles serialization of BigIntegers to fixed-length byte arrays and computation of protocol messages.
    /// </summary>
    public static class SrpEncoding
    {
        /// <summary>
        /// Serializes a <see cref="BigInteger"/> to a big-endian byte array of length ctx.ModulusSize/>.
        /// Used for public keys (A, B) and the modulus N.
        /// </summary>
        /// <param name="ctx">SRP context with cryptographic parameters (hash, N, g, salt, user) for M2 verification.</param>
        /// <param name="value">The value to serialize.</param>
        /// <returns>A byte array of fixed modulus length.</returns>
        public static byte[] ToModulusBytes(SrpContext ctx, BigInteger value) =>
            BigIntegerUtilities.ToFixedLengthBytes(value, ctx.ModulusSize);

        /// <summary>
        /// Serializes a <see cref="BigInteger"/> to a 32-byte big-endian array.
        /// Used for hash outputs such as u, M1, M2, and x (SHA-256).
        /// </summary>
        /// <param name="ctx">SRP context with cryptographic parameters (hash, N, g, salt, user) for M2 verification.</param>
        /// <param name="value">The value to serialize.</param>
        /// <returns>A 32-byte array.</returns>
        public static byte[] ToHashBytes(SrpContext ctx, BigInteger value) =>
            BigIntegerUtilities.ToFixedLengthBytes(value, ctx.HashSize);

        /// <summary>
        /// Computes a hash over one or more modulus-sized values (e.g., u = H(A, B)).
        /// Each input is serialized using <see cref="ToModulusBytes"/> before hashing.
        /// </summary>
        /// <param name="ctx">SRP context with cryptographic parameters (hash, N, g, salt, user) for M2 verification.</param>
        /// <param name="values">The BigInteger values to hash.</param>
        /// <returns>The hash result as a <see cref="BigInteger"/>.</returns>
        public static BigInteger HashModuli(SrpContext ctx, params BigInteger[] values) =>
            BigIntegerUtilities.Hash(ctx.HashAlgorithmName, values.Select(v => ToModulusBytes(ctx, v)).ToArray());

        /// <summary>
        /// Computes a hash over mixed BigInteger values, serializing each as a modulus-sized value.
        /// Typically used for messages like M1 = H(A, B, S).
        /// </summary>
        /// <param name="ctx">SRP context with cryptographic parameters (hash, N, g, salt, user) for M2 verification.</param>
        /// <param name="values">The BigInteger values to hash.</param>
        /// <returns>The hash result as a <see cref="BigInteger"/>.</returns>
        public static BigInteger HashMixed(SrpContext ctx, params BigInteger[] values)
        {
            var buffers = values.Select(v => ToModulusBytes(ctx, v)).ToArray();
            return BigIntegerUtilities.Hash(ctx.HashAlgorithmName, buffers);
        }

        /// <summary>
        /// Computes the client proof message M1 = H(A, B, S).
        /// </summary>
        /// <param name="ctx">SRP context with cryptographic parameters (hash, N, g, salt, user) for M2 verification.</param>
        /// <param name="A">The client's public ephemeral value.</param>
        /// <param name="B">The server's public ephemeral value.</param>
        /// <param name="sessionKeyK">The shared session key.</param>
        /// <returns>The computed M1 value as a <see cref="BigInteger"/>.</returns>
        public static BigInteger ComputeM1(SrpContext ctx, BigInteger A, BigInteger B, byte[] sessionKeyK) =>
        BigIntegerUtilities.Hash(
            ctx.HashAlgorithmName,
            ToModulusBytes(ctx, A),
            ToModulusBytes(ctx, B),
            sessionKeyK
        );

        /// <summary>
        /// Computes the server proof message M2 = H(A, M1, S).
        /// </summary>
        /// <param name="ctx">SRP context with cryptographic parameters (hash, N, g, salt, user) for M2 verification.</param>
        /// <param name="A">The client's public ephemeral value.</param>
        /// <param name="M1">The client's proof message.</param>
        /// <param name="sessionKeyK">The shared session key.</param>
        /// <returns>The computed M2 value as a <see cref="BigInteger"/>.</returns>
        public static BigInteger ComputeM2(SrpContext ctx, BigInteger A, BigInteger M1, byte[] sessionKeyK) =>
        BigIntegerUtilities.Hash(
            ctx.HashAlgorithmName,
            ToModulusBytes(ctx, A),
            ToHashBytes(ctx, M1),
            sessionKeyK
        );

        /// <summary>
        /// 
        /// </summary>
        /// <param name="ctx"></param>
        /// <param name="S"></param>
        /// <returns></returns>
        public static byte[] ComputeSessionKey(SrpContext ctx, BigInteger S)
        {
            byte[] sBytes = ToModulusBytes(ctx, S);
            return BigIntegerUtilities.ComputeHash(ctx.HashAlgorithmName, sBytes);
        }
    }
}