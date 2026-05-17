using System.Numerics;
using System.Security.Cryptography;
using Quantropic.Security.Abstractions;
using Quantropic.Security.Configuration;
using Quantropic.Security.Exceptions;

namespace Quantropic.Security.Srp.Server
{    
    /// <summary>
    /// Server-side implementation of the Secure Remote Password (SRP) protocol.
    /// Handles challenge generation, client proof verification, and server proof creation.
    /// </summary>
    public class SrpServerService : ISrpServer
    {
        /// <summary>
        /// Generates an SRP challenge for the client, including the server's public ephemeral value (B).
        /// </summary>
        /// <param name="login">The user's login identifier.</param>
        /// <param name="verifierBytes">The stored password verifier (v) as a byte array.</param>
        /// <returns>An <see cref="SrpSessionState"/> containing the session data and the challenge value B.</returns>
        public SrpSessionState GetSrpChallenge(string login, byte[] verifierBytes)
        {
            BigInteger v = new(verifierBytes, isUnsigned: true, isBigEndian: true);

            byte[] bBytes = new byte[32];
            RandomNumberGenerator.Fill(bBytes);
            BigInteger b = new(bBytes, isUnsigned: true, isBigEndian: true);

            BigInteger gB = BigInteger.ModPow(SecurityConstants.g, b, SecurityConstants.N);
            BigInteger B = (SecurityConstants.k * v + gB) % SecurityConstants.N;

            var session = new SrpSessionState(
                login,
                Convert.ToBase64String(bBytes),
                Convert.ToBase64String(verifierBytes),
                Convert.ToBase64String(SrpEncoding.ToModulusBytes(B))
            );

            return session;
        }

        /// <summary>
        /// Verifies the client's SRP proof (M1) and, if valid, generates the server's proof (M2).
        /// </summary>
        /// <param name="sessionState">The current SRP session state containing server-side ephemeral data.</param>
        /// <param name="a">The client's public ephemeral value (A), Base64-encoded.</param>
        /// <param name="m1">The client's proof message (M1), Base64-encoded.</param>
        /// <returns>The server's proof message (M2) as a Base64-encoded string.</returns>
        /// <exception cref="SrpVerificationException">Thrown when verification fails or input values are invalid.</exception>
        public string VerifySrpProof(SrpSessionState sessionState, string a, string m1)
        {
            BigInteger A = new(Convert.FromBase64String(a), isUnsigned: true, isBigEndian: true);
            BigInteger M1_client = new(Convert.FromBase64String(m1), isUnsigned: true, isBigEndian: true);
            BigInteger b = new(Convert.FromBase64String(sessionState!.PrivateKeyB), isUnsigned: true, isBigEndian: true);
            BigInteger v = new(Convert.FromBase64String(sessionState.Verifier), isUnsigned: true, isBigEndian: true);
            BigInteger B = new(Convert.FromBase64String(sessionState.PublicKeyB), isUnsigned: true, isBigEndian: true);

            if (v <= 0)
                throw new SrpVerificationException("The verifier is corrupted");

            if (A % SecurityConstants.N == 0)
                throw new SrpVerificationException("Incorrect value of A");

            if (A <= 0 || A >= SecurityConstants.N)
                throw new SrpVerificationException("Invalid A (out of range) value)");

            BigInteger u = CalculateSrpHash((A, 384), (B, 384));

            if (u == 0)
                throw new SrpVerificationException("Error in calculating the parameter u");

            BigInteger vU = BigInteger.ModPow(v, u, SecurityConstants.N);
            BigInteger S = BigInteger.ModPow((A * vU) % SecurityConstants.N, b, SecurityConstants.N);

            BigInteger M1_server = SrpEncoding.ComputeM1(A, B, S);
            
            byte[] m1ServerBytes = SrpEncoding.ToHashBytes(M1_server);
            byte[] m1ClientBytes = SrpEncoding.ToHashBytes(M1_client);
            
             if (!CryptographicOperations.FixedTimeEquals(m1ServerBytes, m1ClientBytes))
                throw new SrpVerificationException("Invalid password");

            BigInteger M2_server = SrpEncoding.ComputeM2(A, M1_client, S);

            return Convert.ToBase64String(SrpEncoding.ToHashBytes(M2_server));
        }

        /// <summary>
        /// Converts a <see cref="BigInteger"/> to a big-endian byte array of fixed length.
        /// Pads with leading zeros if shorter, or truncates the most significant bytes if longer.
        /// </summary>
        /// <param name="value">The value to convert.</param>
        /// <param name="length">The desired output length in bytes.</param>
        /// <returns>A byte array of the specified length.</returns>
        /// <exception cref="ArgumentException">Thrown if the value is too large to fit in the specified length.</exception>
        private byte[] ToFixedLength(BigInteger value, int length)
        {
            byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);

            if (bytes.Length > length)
                throw new ArgumentException("The value is too large for the specified length.", nameof(value));

            if (bytes.Length == length)
                return bytes;

            byte[] padded = new byte[length];
            Buffer.BlockCopy(bytes, 0, padded, length - bytes.Length, bytes.Length);

            return padded;
        }

        /// <summary>
        /// Computes a SHA-256 hash over multiple <see cref="BigInteger"/> values, each serialized to a fixed length.
        /// </summary>
        /// <param name="values">Tuples containing the value and its target serialized length in bytes.</param>
        /// <returns>The hash result as a <see cref="BigInteger"/>.</returns>
        private BigInteger CalculateSrpHash(params (BigInteger value, int length)[] values)
        {
            using var sha256 = SHA256.Create();
            var all = new List<byte>();

            foreach (var (val, len) in values)
                all.AddRange(ToFixedLength(val, len));

            byte[] hash = sha256.ComputeHash(all.ToArray());
            return new BigInteger(hash, isUnsigned: true, isBigEndian: true);
        }
    }
}