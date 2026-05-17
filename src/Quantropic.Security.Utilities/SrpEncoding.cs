using System.Numerics;
using Quantropic.Security.Utilities;

namespace Quantropic.Security.Configuration
{
    /// <summary>
    /// Provides encoding and hashing utilities specific to the SRP protocol.
    /// Handles serialization of BigIntegers to fixed-length byte arrays and computation of protocol messages.
    /// </summary>
    public static class SrpEncoding
    {
        /// <summary>
        /// Serializes a <see cref="BigInteger"/> to a big-endian byte array of length <see cref="SecurityConstants.ModulusSize"/>.
        /// Used for public keys (A, B) and the modulus N.
        /// </summary>
        /// <param name="value">The value to serialize.</param>
        /// <returns>A byte array of fixed modulus length.</returns>
        public static byte[] ToModulusBytes(BigInteger value) =>
            BigIntegerUtilities.ToFixedLengthBytes(value, SecurityConstants.ModulusSize);

        /// <summary>
        /// Serializes a <see cref="BigInteger"/> to a 32-byte big-endian array.
        /// Used for hash outputs such as u, M1, M2, and x (SHA-256).
        /// </summary>
        /// <param name="value">The value to serialize.</param>
        /// <returns>A 32-byte array.</returns>
        public static byte[] ToHashBytes(BigInteger value) =>
            BigIntegerUtilities.ToFixedLengthBytes(value, 32);

        /// <summary>
        /// Computes a hash over one or more modulus-sized values (e.g., u = H(A, B)).
        /// Each input is serialized using <see cref="ToModulusBytes"/> before hashing.
        /// </summary>
        /// <param name="values">The BigInteger values to hash.</param>
        /// <returns>The hash result as a <see cref="BigInteger"/>.</returns>
        public static BigInteger HashModuli(params BigInteger[] values) =>
            BigIntegerUtilities.Hash(values.Select(ToModulusBytes).ToArray());

        /// <summary>
        /// Computes a hash over mixed BigInteger values, serializing each as a modulus-sized value.
        /// Typically used for messages like M1 = H(A, B, S).
        /// </summary>
        /// <param name="values">The BigInteger values to hash.</param>
        /// <returns>The hash result as a <see cref="BigInteger"/>.</returns>
        public static BigInteger HashMixed(params BigInteger[] values)
        {
            var buffers = new List<byte[]>();

            for (int i = 0; i < values.Length; i++)
                buffers.Add(ToModulusBytes(values[i]));

            return BigIntegerUtilities.Hash(buffers.ToArray());
        }

        /// <summary>
        /// Computes a hash over values with explicit serialization rules.
        /// Allows mixing modulus-sized and hash-sized serializations in a single operation.
        /// </summary>
        /// <param name="args">
        /// Tuples containing the value and a flag indicating whether to serialize as modulus-sized (<c>true</c>) or hash-sized (<c>false</c>).
        /// </param>
        /// <returns>The hash result as a <see cref="BigInteger"/>.</returns>
        public static BigInteger HashExplicit(params (BigInteger Value, bool IsModulus)[] args) =>
            BigIntegerUtilities.Hash(
                args.Select(x => x.IsModulus ? ToModulusBytes(x.Value) : ToHashBytes(x.Value)).ToArray()
            );

        /// <summary>
        /// Computes the client proof message M1 = H(A, B, S).
        /// </summary>
        /// <param name="A">The client's public ephemeral value.</param>
        /// <param name="B">The server's public ephemeral value.</param>
        /// <param name="S">The shared session key.</param>
        /// <returns>The computed M1 value as a <see cref="BigInteger"/>.</returns>
        public static BigInteger ComputeM1(BigInteger A, BigInteger B, BigInteger S) =>
        BigIntegerUtilities.Hash(
            ToModulusBytes(A),
            ToModulusBytes(B),
            ToModulusBytes(S)
        );

        /// <summary>
        /// Computes the server proof message M2 = H(A, M1, S).
        /// </summary>
        /// <param name="A">The client's public ephemeral value.</param>
        /// <param name="M1">The client's proof message.</param>
        /// <param name="S">The shared session key.</param>
        /// <returns>The computed M2 value as a <see cref="BigInteger"/>.</returns>
        public static BigInteger ComputeM2(BigInteger A, BigInteger M1, BigInteger S) =>
        BigIntegerUtilities.Hash(
            ToModulusBytes(A),
            ToHashBytes(M1),
            ToModulusBytes(S)
        );
    }
}