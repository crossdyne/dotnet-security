using System.Numerics;
using System.Security.Cryptography;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Configuration;
using Crossdyne.Security.Exceptions;
using Crossdyne.Security.Utilities;

namespace Crossdyne.Security.Srp.Client
{
    /// <inheritdoc />
    public class SrpClientService : ISrpClient
    {
        /// <inheritdoc />
        /// <remarks>
        /// Derives authentication hash via <see cref="ISrpKeyDerivationService.DeriveAuthHashForSrp"/>.
        /// Sensitive buffers (auth hash and private key a) are cleared after use.
        /// </remarks>
        public (string A, string M1, byte[] SessionKeyK) GenerateSrpProof(string login, byte[] authHashBytes, string saltBase64, string bBase64, SrpGroup srpGroup)    
        {
            var srpProfile = SrpProfileRegistry.GetProfile(srpGroup);
            var ctx = SrpContext.FromOptions(srpProfile.Options);

            byte[] salt = BigIntegerUtilities.DecodeBase64ToBytes(saltBase64);
            byte[]? aBytes = null;

            try
            {
                BigInteger x = new(authHashBytes, isBigEndian: true, isUnsigned: true);

                int privateKeySize = Math.Max(32, ctx.ModulusSize / 2);
                aBytes = new byte[privateKeySize];
                BigInteger a;

                do
                {
                    RandomNumberGenerator.Fill(aBytes);
                    a = new BigInteger(aBytes, isBigEndian: true, isUnsigned: true);
                } while (a == 0);

                BigInteger A = BigInteger.ModPow(ctx.G, a, ctx.N);

                if (A <= 0 || A >= ctx.N)
                    throw new SecurityException("Invalid client public key A.");

                byte[] B_bytes = BigIntegerUtilities.DecodeBase64ToBytes(bBase64);
                BigInteger B = new(B_bytes, isBigEndian: true, isUnsigned: true);

                if (B % ctx.N == 0 || B >= ctx.N)
                    throw new SecurityException("Invalid server public key B.");

                BigInteger u = SrpEncoding.HashModuli(ctx, A, B);

                if (u == 0)
                    throw new SrpVerificationException("Error in calculating the parameter u");

                BigInteger gX = BigInteger.ModPow(ctx.G, x, ctx.N);
                BigInteger term = (ctx.K * gX) % ctx.N;
                BigInteger baseBigInt = (B - term + ctx.N) % ctx.N;
                BigInteger exponent = a + (u * x);
                BigInteger S = BigInteger.ModPow(baseBigInt, exponent, ctx.N);

                if (S == 0)
                    throw new SecurityException("Critical error: shared secret S is zero (possible malicious B).");

                byte[] sessionKeyK = SrpEncoding.ComputeSessionKey(ctx, S);
                byte[] m1Bytes = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK, login, salt);

                return (
                    A: Convert.ToBase64String(SrpEncoding.ToModulusBytes(ctx, A)),
                    M1: Convert.ToBase64String(m1Bytes),
                    SessionKeyK: sessionKeyK);
            }
            finally
            {
                if (authHashBytes is not null)
                    CryptographicOperations.ZeroMemory(authHashBytes);

                if (aBytes is not null)
                    CryptographicOperations.ZeroMemory(aBytes);
            }
        }

        /// <inheritdoc />
        public string GenerateSrpVerifier(string authHash, SrpGroup srpGroup)
        {
            var srpProfile = SrpProfileRegistry.GetProfile(srpGroup);
            var ctx = SrpContext.FromOptions(srpProfile.Options);

            byte[] authHashBytes = Convert.FromBase64String(authHash);
            BigInteger x = new(authHashBytes, isUnsigned: true, isBigEndian: true);
            BigInteger v = BigInteger.ModPow(ctx.G, x, ctx.N);

            return Convert.ToBase64String(SrpEncoding.ToModulusBytes(ctx, v));
        }

        /// <inheritdoc />
        public bool VerifyServerM2(string publicA, string m1, byte[] sessionKeyK, string serverM2, SrpGroup srpGroup)
        {
            var srpProfile = SrpProfileRegistry.GetProfile(srpGroup);
            var ctx = SrpContext.FromOptions(srpProfile.Options);
            
            BigInteger A = BigIntegerUtilities.FromBase64(publicA);
            byte[] m1Bytes = BigIntegerUtilities.DecodeBase64ToBytes(m1);

            byte[] computedM2Bytes = SrpEncoding.ComputeM2(ctx, A, m1Bytes, sessionKeyK);
            byte[] serverM2Bytes = BigIntegerUtilities.DecodeBase64ToBytes(serverM2);

            return CryptographicOperations.FixedTimeEquals(computedM2Bytes, serverM2Bytes);
        }
    }
}