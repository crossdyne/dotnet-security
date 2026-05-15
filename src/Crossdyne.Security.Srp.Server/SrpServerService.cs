using System.Numerics;
using System.Security.Cryptography;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Exceptions;
using Crossdyne.Security.Utilities;

namespace Crossdyne.Security.Srp.Server
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
        /// <param name="ctx">SRP context with cryptographic parameters (hash, N, g, salt, user) for M2 verification.</param>
        /// <param name="login">The user's login identifier.</param>
        /// <param name="verifierBytes">The stored password verifier (v) as a byte array.</param>
        /// <returns>An <see cref="SrpSessionState"/> containing the session data and the challenge value B.</returns>
        public SrpSessionState GetSrpChallenge(string login, byte[] verifierBytes, SrpContext ctx)
        {
            BigInteger v = new(verifierBytes, isUnsigned: true, isBigEndian: true);

            byte[] bBytes = new byte[32];
            RandomNumberGenerator.Fill(bBytes);
            BigInteger b = new(bBytes, isUnsigned: true, isBigEndian: true);

            BigInteger gB = BigInteger.ModPow(ctx.G, b, ctx.N);
            BigInteger B = (ctx.K * v + gB) % ctx.N;

            var session = new SrpSessionState(
                login,
                Convert.ToBase64String(bBytes),
                Convert.ToBase64String(verifierBytes),
                Convert.ToBase64String(SrpEncoding.ToModulusBytes(ctx, B))
            );

            return session;
        }

        /// <summary>
        /// Verifies the client's SRP proof (M1) and, if valid, generates the server's proof (M2).
        /// </summary>
        /// <param name="ctx">SRP context with cryptographic parameters (hash, N, g, salt, user) for M2 verification.</param>
        /// <param name="sessionState">The current SRP session state containing server-side ephemeral data.</param>
        /// <param name="a">The client's public ephemeral value (A), Base64-encoded.</param>
        /// <param name="m1">The client's proof message (M1), Base64-encoded.</param>
        /// <returns>The server's proof message (M2) as a Base64-encoded string.</returns>
        /// <exception cref="SrpVerificationException">Thrown when verification fails or input values are invalid.</exception>
        public string VerifySrpProof(SrpSessionState sessionState, string a, string m1, SrpContext ctx)
        {
            BigInteger A = new(Convert.FromBase64String(a), isUnsigned: true, isBigEndian: true);
            BigInteger M1_client = new(Convert.FromBase64String(m1), isUnsigned: true, isBigEndian: true);
            BigInteger b = new(Convert.FromBase64String(sessionState!.PrivateKeyB), isUnsigned: true, isBigEndian: true);
            BigInteger v = new(Convert.FromBase64String(sessionState.Verifier), isUnsigned: true, isBigEndian: true);
            BigInteger B = new(Convert.FromBase64String(sessionState.PublicKeyB), isUnsigned: true, isBigEndian: true);

            if (v <= 0)
                throw new SrpVerificationException("The verifier is corrupted");

            if (A % ctx.N == 0)
                throw new SrpVerificationException("Incorrect value of A");

            if (A <= 0 || A >= ctx.N)
                throw new SrpVerificationException("Invalid A (out of range) value)");

            BigInteger u = SrpEncoding.HashModuli(ctx, A, B);

            if (u == 0)
                throw new SrpVerificationException("Error in calculating the parameter u");

            BigInteger vU = BigInteger.ModPow(v, u, ctx.N);
            BigInteger S = BigInteger.ModPow((A * vU) % ctx.N, b, ctx.N);

            byte[] sessionKeyK = SrpEncoding.ComputeSessionKey(ctx, S);

            BigInteger M1_server = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK);
            
            byte[] m1ServerBytes = SrpEncoding.ToHashBytes(ctx, M1_server);
            byte[] m1ClientBytes = SrpEncoding.ToHashBytes(ctx, M1_client);
            
             if (!CryptographicOperations.FixedTimeEquals(m1ServerBytes, m1ClientBytes))
                throw new SrpVerificationException("Invalid password");

            BigInteger M2_server = SrpEncoding.ComputeM2(ctx, A, M1_client, sessionKeyK);

            return Convert.ToBase64String(SrpEncoding.ToHashBytes(ctx, M2_server));
        }
    }
}