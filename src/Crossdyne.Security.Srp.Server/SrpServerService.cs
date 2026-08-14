using System.Numerics;
using System.Security.Cryptography;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Configuration;
using Crossdyne.Security.Exceptions;
using Crossdyne.Security.Utilities;

namespace Crossdyne.Security.Srp.Server
{    
    /// <inheritdoc />
    public class SrpServerService : ISrpServer
    {
        /// <inheritdoc />
        public SrpSessionState GetSrpChallenge(string login, byte[] verifierBytes, byte[] salt, SrpGroup srpGroup)
        {
            var srpProfile = SrpProfileRegistry.GetProfile(srpGroup);
            var ctx = SrpContext.FromOptions(srpProfile.Options);

            ArgumentNullException.ThrowIfNull(verifierBytes);
            ArgumentException.ThrowIfNullOrEmpty(login);

            BigInteger v = new(verifierBytes, isUnsigned: true, isBigEndian: true);

            if (v <= 0 || v >= ctx.N)
                throw new SrpVerificationException("The verifier is corrupted");

            int privateKeySize = Math.Max(32, ctx.ModulusSize / 2);

            byte[] bBytes;
            BigInteger B;

            while (true)
            {
                bBytes = new byte[privateKeySize];
                RandomNumberGenerator.Fill(bBytes);
                BigInteger b = new(bBytes, isUnsigned: true, isBigEndian: true);

                if (b == 0)
                    continue;

                BigInteger gB = BigInteger.ModPow(ctx.G, b, ctx.N);
                B = (ctx.K * v + gB) % ctx.N;

                if (B != 0)
                    break;
            }

            if (B >= ctx.N)
                throw new SrpVerificationException("Invalid server public key B.");

            var session = new SrpSessionState(
                login,
                bBytes,
                verifierBytes,
                SrpEncoding.ToModulusBytes(ctx, B),
                salt
            );

            return session;
        }

        /// <inheritdoc />
        public string VerifySrpProof(SrpSessionState sessionState, string a, string m1, SrpGroup srpGroup)
        {
            var srpProfile = SrpProfileRegistry.GetProfile(srpGroup);
            var ctx = SrpContext.FromOptions(srpProfile.Options);

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
            
            if (S == 0)
                throw new SecurityException("Critical error: shared secret S is zero (possible malicious A).");

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