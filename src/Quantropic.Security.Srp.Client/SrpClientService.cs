using System.Numerics;
using Quantropic.Security.Abstractions;
using Quantropic.Security.Configuration;
using Quantropic.Security.Cryptography;
using Quantropic.Security.Utilities;

namespace Quantropic.Security.Srp.Client
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
        public (string A, string M1, string S) GenerateSrpProof(string login, string password, string saltBase64, string B_base64)    
        {
            KeyDerivationService keyDerivationService = new();
            CryptoService cryptoService = new();

            string cleanSalt = saltBase64.Replace('-', '+').Replace('_', '/');
            byte[] salt = Convert.FromBase64String(cleanSalt);
            var (_, AuthHash) = keyDerivationService.DeriveKeysFromPassword(login, password, salt);
            byte[] authHashBytes = Convert.FromBase64String(AuthHash);
            BigInteger x = new(authHashBytes, isBigEndian: true, isUnsigned: true);

            byte[] aBytes = cryptoService.GenerateRandomBytes(32);
            BigInteger a = new(aBytes, isBigEndian: true, isUnsigned: true);

            BigInteger A = BigInteger.ModPow(SecurityConstants.g, a, SecurityConstants.N);

            byte[] B_bytes = Convert.FromBase64String(B_base64);
            BigInteger B = new(B_bytes, isBigEndian: true, isUnsigned: true);

            BigInteger u = SrpEncoding.HashModuli(A, B); 
            
            BigInteger gX = BigInteger.ModPow(SecurityConstants.g, x, SecurityConstants.N);
            BigInteger term = (SecurityConstants.k * gX) % SecurityConstants.N;
            BigInteger baseBigInt = (B - term + SecurityConstants.N) % SecurityConstants.N;
            BigInteger exponent = a + (u * x);
            BigInteger S = BigInteger.ModPow(baseBigInt, exponent, SecurityConstants.N);

            BigInteger M1 = SrpEncoding.ComputeM1(A, B, S); 

            return (
                A: Convert.ToBase64String(SrpEncoding.ToModulusBytes(A)),
                M1: Convert.ToBase64String(SrpEncoding.ToHashBytes(M1)),
                S: Convert.ToBase64String(SrpEncoding.ToModulusBytes(S)));
        }

        /// <summary>
        /// Generates the SRP password verifier (v) from the authentication hash.
        /// This value is stored on the server and used to verify the client's proof without storing the password.
        /// </summary>
        /// <param name="authHash">The authentication hash derived from the user's password and salt, Base64-encoded.</param>
        /// <returns>The verifier value (v) as a URL-safe Base64-encoded string.</returns>
        public string GenerateSrpVerifier(string authHash)
        {
            byte[] authHashBytes = Convert.FromBase64String(authHash);
            BigInteger x = new(authHashBytes, isUnsigned: true, isBigEndian: true);
            BigInteger v = BigInteger.ModPow(SecurityConstants.g, x, SecurityConstants.N);

            return Convert.ToBase64String(SrpEncoding.ToModulusBytes(v));
        }

        /// <summary>
        /// Verifies the server's proof message (M2) to authenticate the server to the client.
        /// </summary>
        /// <param name="a">The client's private ephemeral value (a), Base64-encoded.</param>
        /// <param name="m1">The client's proof message (M1), Base64-encoded.</param>
        /// <param name="s">The shared session key (S), Base64-encoded.</param>
        /// <param name="serverM2">The server's proof message (M2), Base64-encoded.</param>
        /// <returns><c>true</c> if the server's proof is valid; otherwise, <c>false</c>.</returns>
        public bool VerifyServerM2(string a, string m1, string s, string serverM2)
        {
            BigInteger A = BigIntegerUtilities.FromBase64(a);
            BigInteger M1 = BigIntegerUtilities.FromBase64(m1);
            BigInteger S = BigIntegerUtilities.FromBase64(s);
            
            BigInteger computedM2 = SrpEncoding.ComputeM2(A, M1, S);

            string computedM2Base64 = Convert.ToBase64String(SrpEncoding.ToHashBytes(computedM2));
            return serverM2 == computedM2Base64;
        }
    }
}