using System.Numerics;
using System.Security.Cryptography;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Exceptions;
using Crossdyne.Security.Utilities;

namespace Crossdyne.Security.Srp.Server
{    
    /// <summary>
    /// Server-side SRP-6a: challenge generation, client proof verification, server proof creation.
    /// </summary>
    public class SrpServerService : ISrpServer
    {
        /// <summary>
        /// Generates server challenge B and session state from verifier.
        /// </summary>
        /// <param name="login">User login.</param>
        /// <param name="verifierBytes">Stored verifier v as byte array.</param>
        /// <param name="ctx">SRP context (hash, N, g, etc.).</param>
        /// <param name="salt">Authentication hash generated during registration</param>
        /// <returns><see cref="SrpSessionState"/> with private b, verifier, and public B.</returns>
        public SrpSessionState GetSrpChallenge(string login, byte[] verifierBytes, byte[] salt, SrpContext ctx)
        {
            ArgumentNullException.ThrowIfNull(verifierBytes);
            ArgumentException.ThrowIfNullOrEmpty(login);

            BigInteger v = new(verifierBytes, isUnsigned: true, isBigEndian: true);

            if (v <= 0 || v >= ctx.N)
                throw new SrpVerificationException("The verifier is corrupted");

            int privateKeySize = Math.Max(32, ctx.ModulusSize / 2);
            byte[] bBytes;
            BigInteger B;
            do
            {
                bBytes = new byte[privateKeySize];
                RandomNumberGenerator.Fill(bBytes);
                BigInteger b = new(bBytes, isUnsigned: true, isBigEndian: true);

                BigInteger gB = BigInteger.ModPow(ctx.G, b, ctx.N);
                B = (ctx.K * v + gB) % ctx.N;
            } while (B == 0);

            var session = new SrpSessionState(
                login,
                bBytes,
                verifierBytes,
                SrpEncoding.ToModulusBytes(ctx, B),
                salt
            );

            return session;
        }

        /// <summary>
        /// Verifies client M1 proof and returns server M2 proof.
        /// </summary>
        /// <param name="sessionState">Server session state.</param>
        /// <param name="a">Client public A (Base64).</param>
        /// <param name="m1">Client proof M1 (Base64).</param>
        /// <param name="ctx">SRP context.</param>
        /// <returns>Server proof M2 as Base64 string.</returns>
        /// <exception cref="SrpVerificationException">Verification failed or invalid input.</exception>
        public string VerifySrpProof(SrpSessionState sessionState, string a, string m1, SrpContext ctx)
        {
            BigInteger A = new(Convert.FromBase64String(a), isUnsigned: true, isBigEndian: true);
            BigInteger b = new(sessionState.PrivateKeyB, isUnsigned: true, isBigEndian: true);
            BigInteger v = new(sessionState.Verifier, isUnsigned: true, isBigEndian: true);
            BigInteger B = new(sessionState.PublicKeyB, isUnsigned: true, isBigEndian: true);

            if (v <= 0 || v >= ctx.N)
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

            byte[] m1ServerBytes = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK, sessionState.Login, sessionState.Salt);
            byte[] m1ClientBytes = Convert.FromBase64String(m1);
            
             if (!CryptographicOperations.FixedTimeEquals(m1ServerBytes, m1ClientBytes))
                throw new SrpVerificationException("Invalid password");

             byte[] m2ServerBytes = SrpEncoding.ComputeM2(ctx, A, m1ClientBytes, sessionKeyK);

            return Convert.ToBase64String(m2ServerBytes);
        }
    }
}