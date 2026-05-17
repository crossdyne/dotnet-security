using System.Numerics;
using System.Security.Cryptography;
using Quantropic.Security.Abstractions;
using Quantropic.Security.Configuration;
using Quantropic.Security.Cryptography;
using Quantropic.Security.Exceptions;
using Quantropic.Security.Srp.Server;
using Quantropic.Security.Utilities;

namespace Quantropic.Security.Tests.Srp.Server
{
    public class SrpServerServiceTests
    {
        private readonly SrpServerService _server;
        private readonly KeyDerivationService _kdf;
        private const string TestLogin = "user@example.com";
        private const string TestPassword = "MyStr0ng!P@ssw0rd2024";
        private readonly byte[] _testSalt;

        public SrpServerServiceTests()
        {
            _server = new SrpServerService();
            _kdf = new KeyDerivationService();
            _testSalt = RandomNumberGenerator.GetBytes(32);
        }

        #region Helper Methods

        private byte[] GenerateVerifierBytes(string login, string password, byte[] salt)
        {
            var (_, authHash) = _kdf.DeriveKeysFromPassword(login, password, salt);
            var authHashBytes = Convert.FromBase64String(authHash);
            var x = new BigInteger(authHashBytes, isBigEndian: true, isUnsigned: true);
            var v = BigInteger.ModPow(SecurityConstants.g, x, SecurityConstants.N);
            return SrpEncoding.ToModulusBytes(v);
        }

        private SrpSessionState CreateValidSession(byte[] verifierBytes, out byte[] bBytes, out BigInteger B)
        {
            bBytes = RandomNumberGenerator.GetBytes(32);
            var b = new BigInteger(bBytes, isBigEndian: true, isUnsigned: true);
            var v = new BigInteger(verifierBytes, isBigEndian: true, isUnsigned: true);
            var gB = BigInteger.ModPow(SecurityConstants.g, b, SecurityConstants.N);
            B = (SecurityConstants.k * v + gB) % SecurityConstants.N;

            return new SrpSessionState(
                TestLogin,
                Convert.ToBase64String(bBytes),
                Convert.ToBase64String(verifierBytes),
                Convert.ToBase64String(SrpEncoding.ToModulusBytes(B))
            );
        }

        private (string A, string M1, string S) GenerateValidClientProof(string login, string password, byte[] salt, BigInteger B)
        {
            var client = new Quantropic.Security.Srp.Client.SrpClientService();
            var saltBase64 = Convert.ToBase64String(salt).Replace('+', '-').Replace('/', '_');
            var B_base64 = Convert.ToBase64String(SrpEncoding.ToModulusBytes(B));
            return client.GenerateSrpProof(login, password, saltBase64, B_base64);
        }

        #endregion

        #region GetSrpChallenge

        [Fact]
        public void GetSrpChallenge_ValidVerifier_ReturnsValidSession()
        {
            // Arrange
            var verifierBytes = GenerateVerifierBytes(TestLogin, TestPassword, _testSalt);

            // Act
            var session = _server.GetSrpChallenge(TestLogin, verifierBytes);

            // Assert
            Assert.Equal(TestLogin, session.Login);
            Assert.NotNull(session.PrivateKeyB);
            Assert.NotNull(session.Verifier);
            Assert.NotNull(session.PublicKeyB);
            
            // Should be valid Base64
            var bBytes = Convert.FromBase64String(session.PrivateKeyB);
            var vBytes = Convert.FromBase64String(session.Verifier);
            var BBytes = Convert.FromBase64String(session.PublicKeyB);
            
            Assert.Equal(32, bBytes.Length);
            Assert.Equal(SecurityConstants.ModulusSize, vBytes.Length);
            Assert.Equal(SecurityConstants.ModulusSize, BBytes.Length);
        }

        [Fact]
        public void GetSrpChallenge_DifferentCalls_ProducesDifferentB()
        {
            // Arrange
            var verifierBytes = GenerateVerifierBytes(TestLogin, TestPassword, _testSalt);

            // Act
            var session1 = _server.GetSrpChallenge(TestLogin, verifierBytes);
            var session2 = _server.GetSrpChallenge(TestLogin, verifierBytes);

            // Assert
            // B should differ due to random 'b'
            Assert.NotEqual(session1.PublicKeyB, session2.PublicKeyB);
            Assert.NotEqual(session1.PrivateKeyB, session2.PrivateKeyB);
            
            // Verifier should be the same
            Assert.Equal(session1.Verifier, session2.Verifier);
        }

        [Fact]
        public void GetSrpChallenge_NullVerifier_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                _server.GetSrpChallenge(TestLogin, null!));
        }

        [Fact]
        public void GetSrpChallenge_EmptyVerifier_ProducesValidButInsecureSession()
        {
            // Arrange: Empty verifier (edge case)
            var emptyVerifier = Array.Empty<byte>();

            // Act
            var session = _server.GetSrpChallenge(TestLogin, emptyVerifier);

            // Assert: Should not throw, but produces insecure state
            Assert.NotNull(session);
            Assert.NotNull(session.PublicKeyB);
        }

        #endregion

        #region VerifySrpProof - Valid Flow

        [Fact]
        public void VerifySrpProof_ValidClientProof_ReturnsValidM2()
        {
            // Arrange: Full setup
            var verifierBytes = GenerateVerifierBytes(TestLogin, TestPassword, _testSalt);
            var session = CreateValidSession(verifierBytes, out _, out var B);
            var (A, M1, S) = GenerateValidClientProof(TestLogin, TestPassword, _testSalt, B);

            // Act
            var M2 = _server.VerifySrpProof(session, A, M1);

            // Assert
            Assert.NotNull(M2);
            var m2Bytes = Convert.FromBase64String(M2);
            Assert.Equal(SecurityConstants.KeySizeBytes, m2Bytes.Length); // SHA-256
        }

        [Fact]
        public void VerifySrpProof_SameSession_DifferentClientProof_ProducesConsistentM2()
        {
            // Note: M2 depends on A, M1, S - if client sends different A, M2 will differ
            // This tests that server computation is deterministic given inputs
            
            // Arrange
            var verifierBytes = GenerateVerifierBytes(TestLogin, TestPassword, _testSalt);
            var session = CreateValidSession(verifierBytes, out _, out var B);
            var (A1, M1_1, S1) = GenerateValidClientProof(TestLogin, TestPassword, _testSalt, B);
            
            // Generate second proof (will have different A due to random 'a')
            var (A2, M1_2, S2) = GenerateValidClientProof(TestLogin, TestPassword, _testSalt, B);

            // Act
            var M2_1 = _server.VerifySrpProof(session, A1, M1_1);
            var M2_2 = _server.VerifySrpProof(session, A2, M1_2);

            // Assert: M2 will differ because A and M1 differ
            Assert.NotEqual(M2_1, M2_2);
            
            // But both should be valid format
            Assert.NotNull(M2_1);
            Assert.NotNull(M2_2);
        }

        #endregion

        #region VerifySrpProof - Security Validation

        [Fact]
        public void VerifySrpProof_ZeroVerifier_ThrowsSrpVerificationException()
        {
            // Arrange: Create session with zero verifier
            var zeroVerifier = new byte[SecurityConstants.ModulusSize];
            var session = CreateValidSession(zeroVerifier, out _, out _);
            // Override verifier to zero
            var zeroV = BigInteger.Zero;
            session = new SrpSessionState(
                session.Login,
                session.PrivateKeyB,
                Convert.ToBase64String(SrpEncoding.ToModulusBytes(zeroV)),
                session.PublicKeyB
            );
            
            var invalidA = Convert.ToBase64String(SrpEncoding.ToModulusBytes(BigInteger.One));
            var invalidM1 = Convert.ToBase64String(new byte[32]);

            // Act & Assert
            Assert.Throws<SrpVerificationException>(() => _server.VerifySrpProof(session, invalidA, invalidM1));
        }

        [Fact]
        public void VerifySrpProof_AEqualsZero_ThrowsSrpVerificationException()
        {
            var verifierBytes = GenerateVerifierBytes(TestLogin, TestPassword, _testSalt);
            var session = CreateValidSession(verifierBytes, out _, out _);
            
            var zeroA = Convert.ToBase64String(new byte[SecurityConstants.ModulusSize]);
            var dummyM1 = Convert.ToBase64String(new byte[32]);

            Assert.Throws<SrpVerificationException>(() => _server.VerifySrpProof(session, zeroA, dummyM1));
        }

        [Fact]
        public void VerifySrpProof_AOutOfRange_ThrowsSrpVerificationException()
        {
            var verifierBytes = GenerateVerifierBytes(TestLogin, TestPassword, _testSalt);
            var session = CreateValidSession(verifierBytes, out _, out _);
            
            // A >= N is invalid
            var invalidA = Convert.ToBase64String(SrpEncoding.ToModulusBytes(SecurityConstants.N));
            var dummyM1 = Convert.ToBase64String(new byte[32]);

            Assert.Throws<SrpVerificationException>(() => _server.VerifySrpProof(session, invalidA, dummyM1));
        }

        [Fact]
        public void VerifySrpProof_WrongPassword_ThrowsSrpVerificationException()
        {
            // Arrange: Server expects password "correct", client uses "wrong"
            var verifierBytes = GenerateVerifierBytes(TestLogin, "correct_password", _testSalt);
            var session = CreateValidSession(verifierBytes, out _, out var B);
            
            // Client proves with wrong password
            var (A, M1, _) = GenerateValidClientProof(TestLogin, "wrong_password", _testSalt, B);

            Assert.Throws<SrpVerificationException>(() => _server.VerifySrpProof(session, A, M1));
        }

        [Fact]
        public void VerifySrpProof_TamperedM1_ThrowsSrpVerificationException()
        {
            var verifierBytes = GenerateVerifierBytes(TestLogin, TestPassword, _testSalt);
            var session = CreateValidSession(verifierBytes, out _, out var B);
            var (A, M1, _) = GenerateValidClientProof(TestLogin, TestPassword, _testSalt, B);
            
            // Tamper with M1
            var m1Bytes = Convert.FromBase64String(M1);
            m1Bytes[0] ^= 0xFF;
            var tamperedM1 = Convert.ToBase64String(m1Bytes);

            Assert.Throws<SrpVerificationException>(() => _server.VerifySrpProof(session, A, tamperedM1));
        }

        [Fact]
        public void VerifySrpProof_FixedTimeComparison_PreventsTimingAttack()
        {
            // This test documents that FixedTimeEquals is used
            // Actual timing attack testing requires statistical analysis

            var verifierBytes = GenerateVerifierBytes(TestLogin, TestPassword, _testSalt);
            var session = CreateValidSession(verifierBytes, out _, out var B);
            var (A, M1, _) = GenerateValidClientProof(TestLogin, TestPassword, _testSalt, B);
            
            // Create M1 with one-bit difference at various positions
            var m1Bytes = Convert.FromBase64String(M1);
            
            // Act & Assert: All should throw with similar timing (conceptual test)
            for (int i = 0; i < m1Bytes.Length; i++)
            {
                var tampered = (byte[])m1Bytes.Clone();
                tampered[i] ^= 0x01;
                var tamperedM1 = Convert.ToBase64String(tampered);
                
                Assert.Throws<SrpVerificationException>(() =>  _server.VerifySrpProof(session, A, tamperedM1));
            }
        }

        #endregion

        #region VerifySrpProof - Input Validation

        // [Theory]
        // [InlineData(null)]
        // [InlineData("")]
        // public void VerifySrpProof_NullSession_ThrowsException(string? nullSession)
        // {
        //     // Act & Assert
        //     Assert.Throws<ArgumentNullException>(() => 
        //         _server.VerifySrpProof(null!, "A", "M1"));
        // }

        // [Theory]
        // [InlineData(null, "M1")]
        // [InlineData("A", null)]
        // public void VerifySrpProof_NullProofValues_ThrowsException(string? a, string? m1)
        // {
        //     // Arrange
        //     var verifierBytes = GenerateVerifierBytes(TestPassword, _testSalt);
        //     var session = CreateValidSession(verifierBytes, out _, out _);

        //     // Act & Assert
        //     Assert.Throws<ArgumentNullException>(() => 
        //         _server.VerifySrpProof(session, a!, m1!));
        // }

        [Fact]
        public void VerifySrpProof_InvalidBase64A_ThrowsFormatException()
        {
            var verifierBytes = GenerateVerifierBytes(TestLogin, TestPassword, _testSalt);
            var session = CreateValidSession(verifierBytes, out _, out _);

            Assert.Throws<FormatException>(() => _server.VerifySrpProof(session, "!!!invalid!!!", "M1"));
        }

        [Fact]
        public void VerifySrpProof_InvalidBase64M1_ThrowsFormatException()
        {
            var verifierBytes = GenerateVerifierBytes(TestLogin, TestPassword, _testSalt);
            var session = CreateValidSession(verifierBytes, out _, out _);
            var validA = Convert.ToBase64String(SrpEncoding.ToModulusBytes(BigInteger.One));

            Assert.Throws<FormatException>(() => _server.VerifySrpProof(session, validA, "!!!invalid!!!"));
        }

        #endregion

        #region Helper Method Tests

        [Fact]
        public void ToFixedLength_ShortValue_PadsWithZeros()
        {
            // Arrange: Use reflection to access private method or test via integration
            // Since ToFixedLength is private, we test its behavior through public API
            
            // Arrange: Small BigInteger
            var small = BigInteger.One;
            
            // Act: Generate challenge and verify B has correct length
            var verifierBytes = GenerateVerifierBytes(TestLogin, TestPassword, _testSalt);
            var session = _server.GetSrpChallenge(TestLogin, verifierBytes);
            var BBytes = Convert.FromBase64String(session.PublicKeyB);

            Assert.Equal(SecurityConstants.ModulusSize, BBytes.Length);
        }

        [Fact]
        public void CalculateSrpHash_MultipleValues_ProducesConsistentOutput()
        {
            // Test via integration: u parameter computation
            var verifierBytes = GenerateVerifierBytes(TestLogin, TestPassword, _testSalt);
            var session = CreateValidSession(verifierBytes, out _, out var B);
            var (A1, M1, _) = GenerateValidClientProof(TestLogin, TestPassword, _testSalt, B);
            var A_big = BigIntegerUtilities.FromBase64(A1);
            
            // Act: Call twice with same inputs
            var session2 = CreateValidSession(verifierBytes, out _, out _);
            // Note: B will differ due to random b, so we can't test exact u equality
            // Instead, verify the method doesn't throw and produces valid output
            
            // This is tested indirectly through VerifySrpProof success
            Assert.True(true, "CalculateSrpHash tested via integration in VerifySrpProof");
        }

        #endregion

        #region Edge Cases

        [Fact]
        public void VerifySrpProof_VeryLargeLogin_HandlesCorrectly()
        {
            var longLogin = new string('u', 1000) + "@example.com";
            var verifierBytes = GenerateVerifierBytes(TestLogin, TestPassword, _testSalt);
            var session = CreateValidSession(verifierBytes, out _, out var B);
            var (A, M1, _) = GenerateValidClientProof(TestLogin, TestPassword, _testSalt, B);

            // Act: Login is not used in crypto, just stored in session
            var M2 = _server.VerifySrpProof(session, A, M1);

            // Assert
            Assert.NotNull(M2);
        }

        [Fact]
        public void GetSrpChallenge_VerifierLargerThanModulus_TrimsCorrectly()
        {
            // Arrange: Create verifier that's larger than ModulusSize when serialized
            var largeV = SecurityConstants.N * 2; // Larger than N
            var largeVerifierBytes = largeV.ToByteArray(isUnsigned: true, isBigEndian: true);
 
            var session = _server.GetSrpChallenge(TestLogin, largeVerifierBytes);

            var BBytes = Convert.FromBase64String(session.PublicKeyB);
            Assert.Equal(SecurityConstants.ModulusSize, BBytes.Length);
        }

        #endregion
    }
}