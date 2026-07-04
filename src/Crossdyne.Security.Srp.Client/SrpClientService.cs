using System.Numerics;
using System.Security.Cryptography;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Cryptography;
using Crossdyne.Security.Exceptions;
using Crossdyne.Security.Utilities;

namespace Crossdyne.Security.Srp.Client
{
    /// <summary>
    /// Client-side SRP-6a implementation: proof generation, verifier creation, server M2 verification.
    /// </summary>
    public class SrpClientService : ISrpClient
    {
        /// <summary>
        /// Generates client proof (A, M1, session key S) from server challenge.
        /// </summary>
        /// <param name="login">User login.</param>
        /// <param name="password">Plaintext password.</param>
        /// <param name="saltBase64">Server salt (URL-safe Base64).</param>
        /// <param name="B_base64">Server public ephemeral B (URL-safe Base64).</param>
        /// <param name="ctx">SRP context (hash algorithm, N, g, etc.).</param>
        /// <returns>Tuple (A, M1, S) as Base64 strings.</returns>
        public (string A, string M1, byte[] SessionKeyK) GenerateSrpProof(string login, string password, string saltBase64, string B_base64, SrpContext ctx)    
        {
            KeyDerivationService keyDerivationService = new();

            byte[] salt = BigIntegerUtilities.DecodeBase64ToBytes(saltBase64);
            byte[] authHashBytes = keyDerivationService.DeriveAuthHashForSrp(login, password, salt, ctx.HashAlgorithmName);

            BigInteger x = new(authHashBytes, isBigEndian: true, isUnsigned: true);

            int privateKeySize = Math.Max(32, ctx.ModulusSize / 2);
            byte[] aBytes = new byte[privateKeySize];
            RandomNumberGenerator.Fill(aBytes);
            BigInteger a = new(aBytes, isBigEndian: true, isUnsigned: true);

            BigInteger A = BigInteger.ModPow(ctx.G, a, ctx.N);

            byte[] B_bytes = Convert.FromBase64String(B_base64);
            BigInteger B = new(B_bytes, isBigEndian: true, isUnsigned: true);

            if (B % ctx.N == 0)
                throw new SecurityException("Invalid server public key B (Zero-Key Attack).");

            BigInteger u = SrpEncoding.HashModuli(ctx, A, B); 
            
            if (u == 0)
                throw new SrpVerificationException("Error in calculating the parameter u");

            BigInteger gX = BigInteger.ModPow(ctx.G, x, ctx.N);
            BigInteger term = (ctx.K * gX) % ctx.N;
            BigInteger baseBigInt = (B - term + ctx.N) % ctx.N;
            BigInteger exponent = a + (u * x);
            BigInteger S = BigInteger.ModPow(baseBigInt, exponent, ctx.N);

            byte[] sessionKeyK = SrpEncoding.ComputeSessionKey(ctx, S);

           byte[] m1Bytes = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK, login, salt); 

            return (
                A: Convert.ToBase64String(SrpEncoding.ToModulusBytes(ctx, A)),
                M1: Convert.ToBase64String(m1Bytes),
                SessionKeyK: sessionKeyK);
        }

        /// <summary>
        /// Computes SRP verifier v = g^x mod N from the authentication hash.
        /// </summary>
        /// <param name="authHash">Auth hash (Base64).</param>
        /// <param name="ctx">SRP context.</param>
        /// <returns>Verifier as URL-safe Base64 string.</returns>
        public string GenerateSrpVerifier(string authHash, SrpContext ctx)
        {
            byte[] authHashBytes = Convert.FromBase64String(authHash);
            BigInteger x = new(authHashBytes, isUnsigned: true, isBigEndian: true);
            BigInteger v = BigInteger.ModPow(ctx.G, x, ctx.N);

            return Convert.ToBase64String(SrpEncoding.ToModulusBytes(ctx, v));
        }

        /// <summary>
        /// Validates the server proof M2 to authenticate the server.
        /// </summary>
        /// <param name="publicA">Client public A (Base64).</param>
        /// <param name="m1">Client proof M1 (Base64).</param>
        /// <param name="sessionKeyK">Session key S (Base64).</param>
        /// <param name="serverM2">Server proof M2 (Base64).</param>
        /// <param name="ctx">SRP context.</param>
        /// <returns>True if the server proof is valid.</returns>
        public bool VerifyServerM2(string publicA, string m1, byte[] sessionKeyK, string serverM2, SrpContext ctx)
        {
            BigInteger A = BigIntegerUtilities.FromBase64(publicA);
            byte[] m1Bytes = Convert.FromBase64String(m1);

            byte[] computedM2Bytes = SrpEncoding.ComputeM2(ctx, A, m1Bytes, sessionKeyK);;
            byte[] serverM2Bytes = Convert.FromBase64String(serverM2);

            return CryptographicOperations.FixedTimeEquals(computedM2Bytes, serverM2Bytes);
        }
    }
}