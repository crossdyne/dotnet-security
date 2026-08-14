using System.Numerics;
using System.Security.Cryptography;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Configuration;
using Crossdyne.Security.Exceptions;
using Crossdyne.Security.Srp.Client;
using Crossdyne.Security.Utilities;

namespace Crossdyne.Security.Tests
{
    public class SrpClientServiceTests
    {
        private readonly SrpClientService srpClient = new();
        private const SrpGroup ValidGroup = SrpGroup.Rfc5054_3072;

        private static SrpContext GetContext(SrpGroup group)
        {
            var profile = SrpProfileRegistry.GetProfile(group);
            return SrpContext.FromOptions(profile.Options);
        }

        private static string ToBase64(BigInteger value, int length) =>
            Convert.ToBase64String(BigIntegerUtilities.ToFixedLengthBytes(value, length));

        #region GenerateSrpProof

        [Fact]
        public void GenerateSrpProof_NullSalt_ThrowsArgumentNullException()
        {
            var ex = Assert.Throws<ArgumentNullException>(() =>
                srpClient.GenerateSrpProof("user", new byte[32], null!, "AA==", ValidGroup));

            Assert.Equal("base64", ex.ParamName);
        }

        [Fact]
        public void GenerateSrpProof_NullB_ThrowsArgumentNullException()
        {
            var ex = Assert.Throws<ArgumentNullException>(() =>
                srpClient.GenerateSrpProof("user", new byte[32], "AA==", null!, ValidGroup));

            Assert.Equal("base64", ex.ParamName);
        }

        [Fact]
        public void GenerateSrpProof_InvalidSaltBase64_ThrowsFormatException()
        {
            Assert.Throws<FormatException>(() =>
                srpClient.GenerateSrpProof("user", new byte[32], "not-base64!!!", "AA==", ValidGroup));
        }

        [Fact]
        public void GenerateSrpProof_InvalidBBase64_ThrowsFormatException()
        {
            Assert.Throws<FormatException>(() =>
                srpClient.GenerateSrpProof("user", new byte[32], "AA==", "not-base64!!!", ValidGroup));
        }

        [Fact]
        public void GenerateSrpProof_B_Zero_ThrowsSecurityException()
        {
            // B = 0 → B % N == 0
            Assert.Throws<SecurityException>(() =>
                srpClient.GenerateSrpProof("user", new byte[32], "AA==", "AA==", ValidGroup));
        }

        [Fact]
        public void GenerateSrpProof_B_EqualsModulus_ThrowsSecurityException()
        {
            var ctx = GetContext(ValidGroup);
            string b = ToBase64(ctx.N, ctx.ModulusSize);

            Assert.Throws<SecurityException>(() =>
                srpClient.GenerateSrpProof("user", new byte[32], "AA==", b, ValidGroup));
        }

        [Fact]
        public void GenerateSrpProof_ValidInputs_ReturnsProofAndZeroesAuthHash()
        {
            var ctx = GetContext(ValidGroup);
            byte[] authHash = Enumerable.Repeat((byte)0xAB, 32).ToArray();
            byte[] salt = Enumerable.Repeat((byte)0xCD, 16).ToArray();
            string saltB64 = Convert.ToBase64String(salt);

            // Генерируем валидный B = g^b mod N
            byte[] bBytes = new byte[32];
            RandomNumberGenerator.Fill(bBytes);
            BigInteger b = new(bBytes, isUnsigned: true, isBigEndian: true);
            BigInteger B = BigInteger.ModPow(ctx.G, b, ctx.N);
            string bB64 = ToBase64(B, ctx.ModulusSize);

            var (A, M1, sessionKeyK) = srpClient.GenerateSrpProof("alice", authHash, saltB64, bB64, ValidGroup);

            Assert.False(string.IsNullOrEmpty(A));
            Assert.False(string.IsNullOrEmpty(M1));
            Assert.NotNull(sessionKeyK);
            Assert.Equal(ctx.HashSize, sessionKeyK.Length);
            Assert.True(authHash.All(b => b == 0)); // sensitive data cleared
        }

        #endregion

        #region GenerateSrpVerifier
       
        [Fact]
        public void GenerateSrpVerifier_NullAuthHash_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => srpClient.GenerateSrpVerifier(null!, ValidGroup));
        }

        [Fact]
        public void GenerateSrpVerifier_InvalidBase64_ThrowsFormatException()
        {
            Assert.Throws<FormatException>(() => srpClient.GenerateSrpVerifier("!!!", ValidGroup));
        }

        [Fact]
        public void GenerateSrpVerifier_ValidHash_ReturnsDeterministicBase64()
        {
            byte[] hash = Enumerable.Repeat((byte)0xAB, 32).ToArray();
            string hashB64 = Convert.ToBase64String(hash);

            string v1 = srpClient.GenerateSrpVerifier(hashB64, ValidGroup);
            string v2 = srpClient.GenerateSrpVerifier(hashB64, ValidGroup);

            Assert.False(string.IsNullOrEmpty(v1));
            Assert.Equal(v1, v2);
        }

        #endregion

        #region VerifyServerM2

        [Fact]
        public void VerifyServerM2_CorrectM2_ReturnsTrue()
        {
            var ctx = GetContext(ValidGroup);
            byte[] sessionKey = new byte[ctx.HashSize];
            RandomNumberGenerator.Fill(sessionKey);

            BigInteger A = BigInteger.ModPow(ctx.G, new BigInteger(123), ctx.N);
            string aB64 = ToBase64(A, ctx.ModulusSize);

            byte[] m1 = new byte[ctx.HashSize];
            RandomNumberGenerator.Fill(m1);
            string m1B64 = Convert.ToBase64String(m1);

            string validM2 = Convert.ToBase64String(
                SrpEncoding.ComputeM2(ctx, A, m1, sessionKey));

            Assert.True(srpClient.VerifyServerM2(aB64, m1B64, sessionKey, validM2, ValidGroup));
        }

        [Fact]
        public void VerifyServerM2_WrongM2_ReturnsFalse()
        {
            var ctx = GetContext(ValidGroup);
            byte[] sessionKey = new byte[ctx.HashSize];
            RandomNumberGenerator.Fill(sessionKey);

            BigInteger A = BigInteger.ModPow(ctx.G, new BigInteger(123), ctx.N);
            string aB64 = ToBase64(A, ctx.ModulusSize);

            byte[] m1 = new byte[ctx.HashSize];
            RandomNumberGenerator.Fill(m1);
            string m1B64 = Convert.ToBase64String(m1);

            byte[] wrongM2 = new byte[ctx.HashSize];
            RandomNumberGenerator.Fill(wrongM2);
            string wrongM2B64 = Convert.ToBase64String(wrongM2);

            Assert.False(srpClient.VerifyServerM2(aB64, m1B64, sessionKey, wrongM2B64, ValidGroup));
        }

        [Fact]
        public void VerifyServerM2_NullPublicA_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() =>
                srpClient.VerifyServerM2(null!, "AA==", new byte[1], "AA==", ValidGroup));
        }

        #endregion
    }
}