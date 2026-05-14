using System.Numerics;
using System.Security.Cryptography;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Cryptography;
using Crossdyne.Security.Exceptions;
using Crossdyne.Security.Utilities;

namespace Crossdyne.Security.Srp.Client
{
    /// <summary>
    /// Client-side implementation of the Secure Remote Password (SRP) protocol.
    /// Handles proof generation, verifier creation, and server authentication verification.
    /// </summary>
    public class SrpClientService : ISrpClient
    {
        /// <summary>
        /// Generates the SRP client proof values required for authentication.
        /// </summary>
        /// <param name="ctx">SRP context with cryptographic parameters (hash, N, g, salt, user) for M2 verification.</param>
        /// <param name="login">User Login.</param>
        /// <param name="password">The user's plain-text password.</param>
        /// <param name="saltBase64">The salt provided by the server, encoded in URL-safe Base64.</param>
        /// <param name="B_base64">The server's public ephemeral value (B), encoded in URL-safe Base64.</param>
        /// <returns>
        /// A tuple containing:
        /// <list type="bullet">
        /// <item><description><c>A</c>: The client's public ephemeral value, Base64-encoded.</description></item>
        /// <item><description><c>M1</c>: The client's proof message (M1), Base64-encoded.</description></item>
        /// <item><description><c>S</c>: The shared session key, Base64-encoded.</description></item>
        /// </list>
        /// </returns>
        public (string A, string M1, string S) GenerateSrpProof(string login, string password, string saltBase64, string B_base64, SrpContext ctx)    
        {
            KeyDerivationService keyDerivationService = new();

            string cleanSalt = saltBase64.Replace('-', '+').Replace('_', '/');
            byte[] salt = Convert.FromBase64String(cleanSalt);
            var (_, AuthHash) = keyDerivationService.DeriveKeysFromPassword(login, password, salt);
            byte[] authHashBytes = Convert.FromBase64String(AuthHash);
            BigInteger x = new(authHashBytes, isBigEndian: true, isUnsigned: true);

            byte[] aBytes = new byte[32];
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

            BigInteger M1 = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK); 

            return (
                A: Convert.ToBase64String(SrpEncoding.ToModulusBytes(ctx, A)),
                M1: Convert.ToBase64String(SrpEncoding.ToHashBytes(ctx, M1)),
                S: Convert.ToBase64String(SrpEncoding.ToModulusBytes(ctx, S)));
        }

        /// <summary>
        /// Generates the SRP password verifier (v) from the authentication hash.
        /// This value is stored on the server and used to verify the client's proof without storing the password.
        /// </summary>
        /// <param name="ctx">SRP context with cryptographic parameters (hash, N, g, salt, user) for M2 verification.</param>
        /// <param name="authHash">The authentication hash derived from the user's password and salt, Base64-encoded.</param>
        /// <returns>The verifier value (v) as a URL-safe Base64-encoded string.</returns>
        public string GenerateSrpVerifier(string authHash, SrpContext ctx)
        {
            byte[] authHashBytes = Convert.FromBase64String(authHash);
            BigInteger x = new(authHashBytes, isUnsigned: true, isBigEndian: true);
            BigInteger v = BigInteger.ModPow(ctx.G, x, ctx.N);

            return Convert.ToBase64String(SrpEncoding.ToModulusBytes(ctx, v));
        }

        /// <summary>
        /// Verifies the server's proof message (M2) to authenticate the server to the client.
        /// </summary>
        /// <param name="ctx">SRP context with cryptographic parameters (hash, N, g, salt, user) for M2 verification.</param>
        /// <param name="publicA">The client's private ephemeral value (publicA), Base64-encoded.</param>
        /// <param name="m1">The client's proof message (M1), Base64-encoded.</param>
        /// <param name="s">The shared session key (S), Base64-encoded.</param>
        /// <param name="serverM2">The server's proof message (M2), Base64-encoded.</param>
        /// <returns><c>true</c> if the server's proof is valid; otherwise, <c>false</c>.</returns>
        public bool VerifyServerM2(string publicA, string m1, string s, string serverM2, SrpContext ctx)
        {
            BigInteger A = BigIntegerUtilities.FromBase64(publicA);
            BigInteger M1 = BigIntegerUtilities.FromBase64(m1);
            BigInteger S = BigIntegerUtilities.FromBase64(s);
            
            byte[] sessionKeyK = SrpEncoding.ComputeSessionKey(ctx ,S);

            BigInteger computedM2 = SrpEncoding.ComputeM2(ctx, A, M1, sessionKeyK);

            byte[] computedM2Bytes = SrpEncoding.ToHashBytes(ctx, computedM2);
            byte[] serverM2Bytes = Convert.FromBase64String(serverM2);

            return CryptographicOperations.FixedTimeEquals(computedM2Bytes, serverM2Bytes);
        }
    }
}