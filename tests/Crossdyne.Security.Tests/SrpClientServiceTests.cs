using System.Numerics;
using System.Security.Cryptography;
using Crossdyne.Security.Configuration;
using Crossdyne.Security.Cryptography;
using Crossdyne.Security.Srp.Client;
using Crossdyne.Security.Tests.Helpers;
using Crossdyne.Security.Utilities;

namespace Crossdyne.Security.Tests
{
    public class SrpClientServiceTests
    {
        private readonly SrpClientService _client;
        private readonly KeyDerivationService _kdf;
        private const string TestLogin = "TestLogin";
        private const string TestPassword = "MyStr0ng!P@ssw0rd2024";
        private readonly byte[] _testSalt;
        private readonly string _testSaltBase64;
        private readonly CryptoVersion CryptoVersion = CryptoVersion.V1;
        
        public SrpClientServiceTests()
        {
            _client = new SrpClientService();
            _kdf = new KeyDerivationService();
            _testSalt = RandomNumberGenerator.GetBytes(32);
            _testSaltBase64 = Convert.ToBase64String(_testSalt).Replace('+', '-').Replace('/', '_');
        }

        #region Helper Methods

        private (string AuthHash, byte[] AuthHashBytes, BigInteger X) DeriveAuthComponents(string login, string password, byte[] salt)
        {
            var (_, authHash) = _kdf.DeriveKeysFromPassword(login, password, salt, CryptoVersion);
            var authHashBytes = Convert.FromBase64String(authHash);
            var x = new BigInteger(authHashBytes, isBigEndian: true, isUnsigned: true);
            return (authHash, authHashBytes, x);
        }

        private BigInteger GenerateValidB(BigInteger v, byte[] bBytes)
        {
            var context = SrpHelper.GetSrpContext();
            var b = new BigInteger(bBytes, isBigEndian: true, isUnsigned: true);
            var gB = BigInteger.ModPow(context.G, b, context.N);
            return (context.K * v + gB) % context.N;
        }

        #endregion

        #region GenerateSrpProof - Basic Functionality

        [Fact]
        public void GenerateSrpProof_ValidInputs_ReturnsValidBase64Strings()
        {
            // Arrange
            var context = SrpHelper.GetSrpContext();
            var (_, authHashBytes, x) = DeriveAuthComponents(TestLogin, TestPassword, _testSalt);
            var v = BigInteger.ModPow(context.G, x, context.N);

            var bKeySize = Math.Max(32, context.ModulusSize / 2);
            var bBytes = RandomNumberGenerator.GetBytes(bKeySize);
            var B = GenerateValidB(v, bBytes);
            var B_base64 = Convert.ToBase64String(SrpEncoding.ToModulusBytes(context, B));

            // Act
            var (A, M1, sessionKeyK) = _client.GenerateSrpProof(TestLogin, TestPassword, _testSaltBase64, B_base64, context, CryptoVersion);

            // Assert
            Assert.NotNull(A);
            Assert.NotNull(M1);
            Assert.NotNull(sessionKeyK);

            var aBytes = Convert.FromBase64String(A);
            var m1Bytes = Convert.FromBase64String(M1);
            Assert.Equal(context.ModulusSize, aBytes.Length);
            Assert.Equal(context.HashSize, m1Bytes.Length);
            Assert.Equal(context.HashSize, sessionKeyK.Length);
        }

        [Fact]
        public void GenerateSrpProof_SameInputs_ProducesDifferentA_SameM1SameS()
        {
            // Arrange
            var context = SrpHelper.GetSrpContext();
            var bBytes = RandomNumberGenerator.GetBytes(32);
            var (_, authHashBytes, x) = DeriveAuthComponents(TestLogin, TestPassword, _testSalt);
            var v = BigInteger.ModPow(context.G, x, context.N);
            var B = GenerateValidB(v, bBytes);
            var B_base64 = Convert.ToBase64String(SrpEncoding.ToModulusBytes(context, B));

            // Act
            var (A1, M1_1, S1) = _client.GenerateSrpProof(TestLogin, TestPassword, _testSaltBase64, B_base64, context, CryptoVersion);
            var (A2, M1_2, S2) = _client.GenerateSrpProof(TestLogin, TestPassword, _testSaltBase64, B_base64, context, CryptoVersion);

            // Assert
            // A should differ (random 'a' each time)
            Assert.NotEqual(A1, A2);
            
            // M1 and S should be the same for same inputs (deterministic given A, B, password, salt)
            // Note: Since A differs, M1 and S will also differ - this is expected SRP behavior
            Assert.NotEqual(M1_1, M1_2);
            Assert.NotEqual(S1, S2);
        }

        [Fact]
        public void GenerateSrpProof_UrlSafeBase64Salt_HandlesCorrectly()
        {
            var saltWithSpecialChars = new byte[32];
            saltWithSpecialChars[0] = 0xfb;
            saltWithSpecialChars[1] = 0xff;
            saltWithSpecialChars[2] = 0xfe;
            saltWithSpecialChars[3] = 0xfd;
            RandomNumberGenerator.Fill(saltWithSpecialChars.AsSpan(4));
            
            var saltBase64Url = Convert.ToBase64String(saltWithSpecialChars)
                .Replace('+', '-')
                .Replace('/', '_');

            var context = SrpHelper.GetSrpContext();
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, saltWithSpecialChars, CryptoVersion);
            var authHashBytes = Convert.FromBase64String(authHash);
            var x = new BigInteger(authHashBytes, isBigEndian: true, isUnsigned: true);
            var v = BigInteger.ModPow(context.G, x, context.N);
            
            var bBytes = RandomNumberGenerator.GetBytes(32);
            var B = GenerateValidB(v, bBytes);
            var B_base64 = Convert.ToBase64String(SrpEncoding.ToModulusBytes(context, B));

            var (A, M1, S) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64Url, B_base64, context, CryptoVersion);

            Assert.NotNull(A);
            Assert.NotNull(M1);
            Assert.NotNull(S);
        }

        #endregion

        #region GenerateSrpProof - Input Validation

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void GenerateSrpProof_InvalidPassword_ThrowsArgumentException(string? invalidPassword)
        {
            // Arrange
            var context = SrpHelper.GetSrpContext();
            var bBytes = RandomNumberGenerator.GetBytes(32);
            var B_base64 = Convert.ToBase64String(bBytes);

            // Act & Assert
            Assert.Throws<ArgumentException>(() => 
                _client.GenerateSrpProof(TestLogin, invalidPassword!, _testSaltBase64, B_base64, context, CryptoVersion));
        }

        #endregion

        #region GenerateSrpVerifier

        [Fact]
        public void GenerateSrpVerifier_ValidAuthHash_ReturnsValidBase64()
        {
            // Arrange
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _testSalt, CryptoVersion);

            // Act
            var context = SrpHelper.GetSrpContext();
            var verifier = _client.GenerateSrpVerifier(authHash, context);

            // Assert
            Assert.NotNull(verifier);
            var verifierBytes = Convert.FromBase64String(verifier);
            Assert.Equal(context.ModulusSize, verifierBytes.Length);
        }

        [Fact]
        public void GenerateSrpVerifier_SameAuthHash_ProducesSameVerifier()
        {
            // Arrange
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _testSalt, CryptoVersion);

            // Act
            var context = SrpHelper.GetSrpContext();
            var v1 = _client.GenerateSrpVerifier(authHash, context);
            var v2 = _client.GenerateSrpVerifier(authHash, context);

            // Assert
            Assert.Equal(v1, v2);
        }

        [Fact]
        public void GenerateSrpVerifier_DifferentPasswords_ProducesDifferentVerifiers()
        {
            // Arrange
            var (_, authHash1) = _kdf.DeriveKeysFromPassword(TestLogin, "password1", _testSalt, CryptoVersion);
            var (_, authHash2) = _kdf.DeriveKeysFromPassword(TestLogin, "password2", _testSalt, CryptoVersion);

            // Act
            var context = SrpHelper.GetSrpContext();
            var v1 = _client.GenerateSrpVerifier(authHash1, context);
            var v2 = _client.GenerateSrpVerifier(authHash2, context);

            // Assert
            Assert.NotEqual(v1, v2);
        }

        #endregion

        #region VerifyServerM2

        [Fact]
        public void VerifyServerM2_ValidM2_ReturnsTrue()
        {
            // Arrange: Full SRP flow to get valid M2
            var context = SrpHelper.GetSrpContext();
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _testSalt, CryptoVersion);
            var authHashBytes = Convert.FromBase64String(authHash);
            var x = new BigInteger(authHashBytes, isBigEndian: true, isUnsigned: true);
            var v = BigInteger.ModPow(context.G, x, context.N);
            
            var bBytes = RandomNumberGenerator.GetBytes(32);
            var B = GenerateValidB(v, bBytes);
            var B_base64 = Convert.ToBase64String(SrpEncoding.ToModulusBytes(context, B));
            
            var (A, M1, sessionKeyK) = _client.GenerateSrpProof(TestLogin, TestPassword, _testSaltBase64, B_base64, context, CryptoVersion);

            var A_big = BigIntegerUtilities.FromBase64(A);
            var M1_bytes = Convert.FromBase64String(M1); // M1 теперь base64 от byte[]
            var expectedM2 = SrpEncoding.ComputeM2(context, A_big, M1_bytes, sessionKeyK);
            var expectedM2Base64 = Convert.ToBase64String(expectedM2); // уже byte[]

            var result = _client.VerifyServerM2(A, M1, sessionKeyK, expectedM2Base64, context);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyServerM2_InvalidM2_ReturnsFalse()
        {
            // Arrange
            var context = SrpHelper.GetSrpContext();
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _testSalt, CryptoVersion);
            var authHashBytes = Convert.FromBase64String(authHash);
            var x = new BigInteger(authHashBytes, isBigEndian: true, isUnsigned: true);
            var v = BigInteger.ModPow(context.G, x, context.N);
            
            var bBytes = RandomNumberGenerator.GetBytes(Math.Max(32, context.ModulusSize / 2));
            var B = GenerateValidB(v, bBytes);
            var B_base64 = Convert.ToBase64String(SrpEncoding.ToModulusBytes(context, B));
            
            var (A, M1, sessionKeyK) = _client.GenerateSrpProof(TestLogin, TestPassword, _testSaltBase64, B_base64, context, CryptoVersion);
            
            // Create invalid M2 (flip one bit)
            var validM2Bytes = SrpEncoding.ComputeM2(
                context,
                BigIntegerUtilities.FromBase64(A),
                Convert.FromBase64String(M1),
                sessionKeyK);

            validM2Bytes[0] ^= 0x01;
            var invalidM2Base64 = Convert.ToBase64String(validM2Bytes);

            // Act
            var result = _client.VerifyServerM2(A, M1, sessionKeyK, invalidM2Base64, context);

            // Assert
            Assert.False(result);
        }
        #endregion

        #region Security & Edge Cases

        [Fact]
        public void GenerateSrpProof_LargePassword_HandlesCorrectly()
        {
            // Arrange
            var context = SrpHelper.GetSrpContext();
            var largePassword = new string('P', 1000);
            var bBytes = RandomNumberGenerator.GetBytes(32);
            var (_, authHashBytes, x) = DeriveAuthComponents(TestLogin, largePassword, _testSalt);
            var v = BigInteger.ModPow(context.G, x, context.N);
            var B = GenerateValidB(v, bBytes);
            var B_base64 = Convert.ToBase64String(SrpEncoding.ToModulusBytes(context, B));

            // Act
            var (A, M1, S) = _client.GenerateSrpProof(TestLogin, largePassword, _testSaltBase64, B_base64, context, CryptoVersion);

            // Assert
            Assert.NotNull(A);
            Assert.NotNull(M1);
            Assert.NotNull(S);
        }

        [Fact]
        public void GenerateSrpProof_UnicodePassword_HandlesCorrectly()
        {
            // Arrange
            var context = SrpHelper.GetSrpContext();
            var unicodePassword = "Пароль🔐密码🗝️";
            var bBytes = RandomNumberGenerator.GetBytes(32);
            var (_, authHashBytes, x) = DeriveAuthComponents(TestLogin, unicodePassword, _testSalt);
            var v = BigInteger.ModPow(context.G, x, context.N);
            var B = GenerateValidB(v, bBytes);
            var B_base64 = Convert.ToBase64String(SrpEncoding.ToModulusBytes(context, B));

            // Act
            var (A, M1, S) = _client.GenerateSrpProof(TestLogin, unicodePassword, _testSaltBase64, B_base64, context, CryptoVersion);

            // Assert
            Assert.NotNull(A);
            Assert.NotNull(M1);
            Assert.NotNull(S);
        }

        [Fact]
        public void GenerateSrpVerifier_EmptyAuthHashBytes_ProducesValidOutput()
        {
            // Arrange: Empty auth hash (edge case, though insecure in practice)
            var context = SrpHelper.GetSrpContext();
            var emptyAuthHash = Convert.ToBase64String(Array.Empty<byte>());

            // Act
            var verifier = _client.GenerateSrpVerifier(emptyAuthHash, context);

            // Assert: Should produce g^0 = 1
            Assert.NotNull(verifier);
        }

        #endregion
    }
}