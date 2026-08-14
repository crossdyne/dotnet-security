using System.Numerics;
using System.Security.Cryptography;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Configuration;
using Crossdyne.Security.Exceptions;
using Crossdyne.Security.Srp.Client;
using Crossdyne.Security.Srp.Server;
using Crossdyne.Security.Utilities;

namespace Crossdyne.Security.Tests
{
    public class SrpServerServiceTests
    {
        private readonly SrpServerService srpServer = new();
        private const SrpGroup ValidGroup = SrpGroup.Rfc5054_3072;

        private static SrpContext Ctx => 
            SrpContext.FromOptions(SrpProfileRegistry.GetProfile(ValidGroup).Options);

        private static byte[] ValidSalt()
        {
            byte[] s = new byte[16];
            RandomNumberGenerator.Fill(s);
            return s;
        }

        private static byte[] ValidVerifier()
        {
            byte[] hash = new byte[32];
            RandomNumberGenerator.Fill(hash);
            BigInteger x = new(hash, isUnsigned: true, isBigEndian: true);
            BigInteger v = BigInteger.ModPow(Ctx.G, x, Ctx.N);
            return BigIntegerUtilities.ToFixedLengthBytes(v, Ctx.ModulusSize);
        }

        #region GetSrpChallenge

        [Fact]
        public void GetSrpChallenge_NullVerifier_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() =>
                srpServer.GetSrpChallenge("alice", null!, ValidSalt(), ValidGroup));
        }

        [Fact]
        public void GetSrpChallenge_NullLogin_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() =>
                srpServer.GetSrpChallenge(null!, ValidVerifier(), ValidSalt(), ValidGroup));
        }

        [Fact]
        public void GetSrpChallenge_EmptyLogin_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() =>
                srpServer.GetSrpChallenge("", ValidVerifier(), ValidSalt(), ValidGroup));
        }

        [Fact]
        public void GetSrpChallenge_ZeroVerifier_ThrowsSrpVerificationException()
        {
            byte[] zeroV = new byte[Ctx.ModulusSize]; // все нули

            Assert.Throws<SrpVerificationException>(() =>
                srpServer.GetSrpChallenge("alice", zeroV, ValidSalt(), ValidGroup));
        }

        [Fact]
        public void GetSrpChallenge_VerifierEqualToModulus_ThrowsSrpVerificationException()
        {
            byte[] nBytes = BigIntegerUtilities.ToFixedLengthBytes(Ctx.N, Ctx.ModulusSize);

            Assert.Throws<SrpVerificationException>(() =>
                srpServer.GetSrpChallenge("alice", nBytes, ValidSalt(), ValidGroup));
        }

        [Fact]
        public void GetSrpChallenge_ValidInputs_ReturnsStateWithNonZeroB()
        {
            byte[] salt = ValidSalt();
            byte[] verifier = ValidVerifier();

            var state = srpServer.GetSrpChallenge("alice", verifier, salt, ValidGroup);

            Assert.Equal("alice", state.Login);
            Assert.Equal(salt, state.Salt);
            Assert.Equal(verifier, state.Verifier);
            Assert.NotNull(state.PrivateKeyB);
            Assert.True(state.PrivateKeyB.Length > 0);
            Assert.NotNull(state.PublicKeyB);
            Assert.True(state.PublicKeyB.Length > 0);
        }

        #endregion

        #region VerifySrpProof

        [Fact]
        public void VerifySrpProof_InvalidABase64_ThrowsFormatException()
        {
            var state = CreateDummyState();

            Assert.Throws<FormatException>(() =>
                srpServer.VerifySrpProof(state, "!!!", "AA==", ValidGroup));
        }

        [Fact]
        public void VerifySrpProof_AIsZero_ThrowsSrpVerificationException()
        {
            var state = CreateDummyState();

            var ex = Assert.Throws<SrpVerificationException>(() =>
                srpServer.VerifySrpProof(state, "AA==", "AA==", ValidGroup));

            Assert.Contains("Incorrect value of A", ex.Message);
        }

        [Fact]
        public void VerifySrpProof_CorruptedVerifierInState_ThrowsSrpVerificationException()
        {
            var state = new SrpSessionState(
                "alice",
                new byte[32],
                new byte[Ctx.ModulusSize], // v = 0
                new byte[Ctx.ModulusSize],
                ValidSalt());

            Assert.Throws<SrpVerificationException>(() =>
                srpServer.VerifySrpProof(state, "AA==", "AA==", ValidGroup));
        }

        [Fact]
        public void VerifySrpProof_WrongM1_ThrowsSrpVerificationException()
        {
            // Генерируем валидный challenge
            byte[] salt = ValidSalt();
            byte[] verifier = ValidVerifier();
            var state = srpServer.GetSrpChallenge("alice", verifier, salt, ValidGroup);

            // Подсовываем случайный M1
            byte[] fakeM1 = new byte[Ctx.HashSize];
            RandomNumberGenerator.Fill(fakeM1);

            var ex = Assert.Throws<SrpVerificationException>(() =>
                srpServer.VerifySrpProof(state, Convert.ToBase64String(state.PublicKeyB), Convert.ToBase64String(fakeM1), ValidGroup));

            Assert.Contains("Invalid password", ex.Message);
        }
        
        [Fact]
        public void VerifySrpProof_ValidClientProof_ReturnsM2()
        {
            var client = new SrpClientService();
            byte[] salt = ValidSalt();
            string saltB64 = Convert.ToBase64String(salt);

            // Генерируем authHash и verifier
            byte[] authHash = new byte[32];
            RandomNumberGenerator.Fill(authHash);
            string verifierB64 = client.GenerateSrpVerifier(Convert.ToBase64String(authHash), ValidGroup);
            byte[] verifierBytes = Convert.FromBase64String(verifierB64);

            // Сервер выдаёт challenge
            var state = srpServer.GetSrpChallenge("alice", verifierBytes, salt, ValidGroup);
            string bB64 = Convert.ToBase64String(state.PublicKeyB);

            // Клиент считает proof
            var (a, m1, sessionKeyK) = client.GenerateSrpProof("alice", authHash, saltB64, bB64, ValidGroup);

            // Сервер верифицирует и возвращает M2
            string m2 = srpServer.VerifySrpProof(state, a, m1, ValidGroup);

            Assert.False(string.IsNullOrEmpty(m2));

            // Убеждаемся, что клиент тоже принимает этот M2
            Assert.True(client.VerifyServerM2(a, m1, sessionKeyK, m2, ValidGroup));
        }

        #endregion

        private static SrpSessionState CreateDummyState()
        {
            byte[] dummyB = new byte[Ctx.ModulusSize];
            RandomNumberGenerator.Fill(dummyB);

            return new SrpSessionState(
                "alice",
                new byte[32],
                ValidVerifier(),
                dummyB,
                ValidSalt());
        }
    }
}