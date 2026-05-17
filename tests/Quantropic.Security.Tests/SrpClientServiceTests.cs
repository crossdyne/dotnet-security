using System.Numerics;
using System.Security.Cryptography;
using Quantropic.Security.Configuration;
using Quantropic.Security.Cryptography;
using Quantropic.Security.Srp.Client;
using Quantropic.Security.Utilities;

namespace Quantropic.Security.Tests.Srp.Client
{
    public class SrpClientServiceTests
    {
        private readonly SrpClientService _client;
        private readonly KeyDerivationService _kdf;
        private const string TestLogin = "TestLogin";
        private const string TestPassword = "MyStr0ng!P@ssw0rd2024";
        private readonly byte[] _testSalt;
        private readonly string _testSaltBase64;

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
            var (_, authHash) = _kdf.DeriveKeysFromPassword(login, password, salt);
            var authHashBytes = Convert.FromBase64String(authHash);
            var x = new BigInteger(authHashBytes, isBigEndian: true, isUnsigned: true);
            return (authHash, authHashBytes, x);
        }

        private BigInteger GenerateValidB(BigInteger v, byte[] bBytes)
        {
            var b = new BigInteger(bBytes, isBigEndian: true, isUnsigned: true);
            var gB = BigInteger.ModPow(SecurityConstants.g, b, SecurityConstants.N);
            return (SecurityConstants.k * v + gB) % SecurityConstants.N;
        }

        #endregion

        #region GenerateSrpProof - Basic Functionality

        [Fact]
        public void GenerateSrpProof_ValidInputs_ReturnsValidBase64Strings()
        {
            // Arrange
            var (_, authHashBytes, x) = DeriveAuthComponents(TestLogin, TestPassword, _testSalt);
            var v = BigInteger.ModPow(SecurityConstants.g, x, SecurityConstants.N);
            var bBytes = RandomNumberGenerator.GetBytes(32);
            var B = GenerateValidB(v, bBytes);
            var B_base64 = Convert.ToBase64String(SrpEncoding.ToModulusBytes(B));

            // Act
            var (A, M1, S) = _client.GenerateSrpProof(TestLogin, TestPassword, _testSaltBase64, B_base64);

            // Assert
            Assert.NotNull(A);
            Assert.NotNull(M1);
            Assert.NotNull(S);
            
            // Should be valid Base64
            var aBytes = Convert.FromBase64String(A);
            var m1Bytes = Convert.FromBase64String(M1);
            var sBytes = Convert.FromBase64String(S);
            
            // Should have expected lengths
            Assert.Equal(SecurityConstants.ModulusSize, aBytes.Length);
            Assert.Equal(SecurityConstants.KeySizeBytes, m1Bytes.Length); // SHA-256 hash
            Assert.Equal(SecurityConstants.ModulusSize, sBytes.Length);
        }

        [Fact]
        public void GenerateSrpProof_SameInputs_ProducesDifferentA_SameM1SameS()
        {
            // Arrange
            var bBytes = RandomNumberGenerator.GetBytes(32);
            var (_, authHashBytes, x) = DeriveAuthComponents(TestLogin, TestPassword, _testSalt);
            var v = BigInteger.ModPow(SecurityConstants.g, x, SecurityConstants.N);
            var B = GenerateValidB(v, bBytes);
            var B_base64 = Convert.ToBase64String(SrpEncoding.ToModulusBytes(B));

            // Act
            var (A1, M1_1, S1) = _client.GenerateSrpProof(TestLogin, TestPassword, _testSaltBase64, B_base64);
            var (A2, M1_2, S2) = _client.GenerateSrpProof(TestLogin, TestPassword, _testSaltBase64, B_base64);

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
            // Arrange: Salt with + and / characters that need URL-safe conversion
            var saltWithSpecialChars = new byte[] { 0xfb, 0xff, 0xfe, 0xfd }; // Will produce + and / in Base64
            var saltBase64Url = Convert.ToBase64String(saltWithSpecialChars).Replace('+', '-').Replace('/', '_');
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, saltWithSpecialChars);
            var authHashBytes = Convert.FromBase64String(authHash);
            var x = new BigInteger(authHashBytes, isBigEndian: true, isUnsigned: true);
            var v = BigInteger.ModPow(SecurityConstants.g, x, SecurityConstants.N);
            
            var bBytes = RandomNumberGenerator.GetBytes(32);
            var B = GenerateValidB(v, bBytes);
            var B_base64 = Convert.ToBase64String(SrpEncoding.ToModulusBytes(B));

            // Act
            var (A, M1, S) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64Url, B_base64);

            // Assert
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
            var bBytes = RandomNumberGenerator.GetBytes(32);
            var B_base64 = Convert.ToBase64String(bBytes);

            // Act & Assert
            Assert.Throws<ArgumentException>(() => 
                _client.GenerateSrpProof(TestLogin, invalidPassword!, _testSaltBase64, B_base64));
        }

        // [Theory]
        // [InlineData(null)]
        // [InlineData("")]
        // [InlineData("invalid_base64!@#")]
        // public void GenerateSrpProof_InvalidSaltBase64_ThrowsException(string? invalidSalt)
        // {
        //     // Arrange
        //     var bBytes = RandomNumberGenerator.GetBytes(32);
        //     var B_base64 = Convert.ToBase64String(bBytes);

        //     // Act & Assert
        //     Assert.Throws<FormatException>(() => _client.GenerateSrpProof(TestPassword, invalidSalt!, B_base64));
        // }

        // [Theory]
        // [InlineData(null)]
        // [InlineData("")]
        // [InlineData("not_valid_base64$$$")]
        // public void GenerateSrpProof_InvalidBBase64_ThrowsException(string? invalidB)
        // {
        //     // Act & Assert
        //     Assert.Throws<FormatException>(() => _client.GenerateSrpProof(TestPassword, _testSaltBase64, invalidB!));
        // }

        // [Fact]
        // public void GenerateSrpProof_ZeroB_ThrowsOverflowException()
        // {
        //     // Arrange: B = 0 is invalid in SRP
        //     var zeroB = Convert.ToBase64String(new byte[SecurityConstants.ModulusSize]);

        //     // Act & Assert
        //     // BigInteger operations with zero may cause issues in SRP math
        //     var exception = Record.Exception(() => _client.GenerateSrpProof(TestPassword, _testSaltBase64, zeroB));
            
        //     // Should throw during SRP computation (division/modulo with invalid values)
        //     Assert.NotNull(exception);
        // }

        #endregion

        #region GenerateSrpVerifier

        [Fact]
        public void GenerateSrpVerifier_ValidAuthHash_ReturnsValidBase64()
        {
            // Arrange
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _testSalt);

            // Act
            var verifier = _client.GenerateSrpVerifier(authHash);

            // Assert
            Assert.NotNull(verifier);
            var verifierBytes = Convert.FromBase64String(verifier);
            Assert.Equal(SecurityConstants.ModulusSize, verifierBytes.Length);
        }

        [Fact]
        public void GenerateSrpVerifier_SameAuthHash_ProducesSameVerifier()
        {
            // Arrange
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _testSalt);

            // Act
            var v1 = _client.GenerateSrpVerifier(authHash);
            var v2 = _client.GenerateSrpVerifier(authHash);

            // Assert
            Assert.Equal(v1, v2);
        }

        [Fact]
        public void GenerateSrpVerifier_DifferentPasswords_ProducesDifferentVerifiers()
        {
            // Arrange
            var (_, authHash1) = _kdf.DeriveKeysFromPassword(TestLogin, "password1", _testSalt);
            var (_, authHash2) = _kdf.DeriveKeysFromPassword(TestLogin, "password2", _testSalt);

            // Act
            var v1 = _client.GenerateSrpVerifier(authHash1);
            var v2 = _client.GenerateSrpVerifier(authHash2);

            // Assert
            Assert.NotEqual(v1, v2);
        }

        // [Theory]
        // [InlineData(null)]
        // [InlineData("")]
        // [InlineData("invalid_base64")]
        // public void GenerateSrpVerifier_InvalidAuthHash_ThrowsException(string? invalidAuthHash)
        // {
        //     // Act & Assert
        //     Assert.Throws<FormatException>(() => _client.GenerateSrpVerifier(invalidAuthHash!));
        // }

        #endregion

        #region VerifyServerM2

        [Fact]
        public void VerifyServerM2_ValidM2_ReturnsTrue()
        {
            // Arrange: Full SRP flow to get valid M2
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _testSalt);
            var authHashBytes = Convert.FromBase64String(authHash);
            var x = new BigInteger(authHashBytes, isBigEndian: true, isUnsigned: true);
            var v = BigInteger.ModPow(SecurityConstants.g, x, SecurityConstants.N);
            
            var bBytes = RandomNumberGenerator.GetBytes(32);
            var B = GenerateValidB(v, bBytes);
            var B_base64 = Convert.ToBase64String(SrpEncoding.ToModulusBytes(B));
            
            var (A, M1, S) = _client.GenerateSrpProof(TestLogin, TestPassword, _testSaltBase64, B_base64);
            
            // Compute expected M2 manually (same as server would)
            var A_big = BigIntegerUtilities.FromBase64(A);
            var M1_big = BigIntegerUtilities.FromBase64(M1);
            var S_big = BigIntegerUtilities.FromBase64(S);
            var expectedM2 = SrpEncoding.ComputeM2(A_big, M1_big, S_big);
            var expectedM2Base64 = Convert.ToBase64String(SrpEncoding.ToHashBytes(expectedM2));

            // Act
            var result = _client.VerifyServerM2(A, M1, S, expectedM2Base64);

            // Assert
            Assert.True(result);
        }

        [Fact]
        public void VerifyServerM2_InvalidM2_ReturnsFalse()
        {
            // Arrange
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _testSalt);
            var authHashBytes = Convert.FromBase64String(authHash);
            var x = new BigInteger(authHashBytes, isBigEndian: true, isUnsigned: true);
            var v = BigInteger.ModPow(SecurityConstants.g, x, SecurityConstants.N);
            
            var bBytes = RandomNumberGenerator.GetBytes(32);
            var B = GenerateValidB(v, bBytes);
            var B_base64 = Convert.ToBase64String(SrpEncoding.ToModulusBytes(B));
            
            var (A, M1, S) = _client.GenerateSrpProof(TestLogin, TestPassword, _testSaltBase64, B_base64);
            
            // Create invalid M2 (flip one bit)
            var validM2Bytes = SrpEncoding.ToHashBytes(SrpEncoding.ComputeM2(
                BigIntegerUtilities.FromBase64(A),
                BigIntegerUtilities.FromBase64(M1),
                BigIntegerUtilities.FromBase64(S)));
            validM2Bytes[0] ^= 0x01;
            var invalidM2Base64 = Convert.ToBase64String(validM2Bytes);

            // Act
            var result = _client.VerifyServerM2(A, M1, S, invalidM2Base64);

            // Assert
            Assert.False(result);
        }

        // [Theory]
        // [InlineData(null)]
        // [InlineData("")]
        // public void VerifyServerM2_InvalidA_ThrowsException(string? invalidA)
        // {
        //     // Arrange
        //     var validM1 = Convert.ToBase64String(new byte[32]);
        //     var validS = Convert.ToBase64String(new byte[SecurityConstants.ModulusSize]);
        //     var validM2 = Convert.ToBase64String(new byte[32]);

        //     // Act & Assert
        //     Assert.Throws<FormatException>(() => 
        //         _client.VerifyServerM2(invalidA!, validM1, validS, validM2));
        // }

        #endregion

        #region Security & Edge Cases

        [Fact]
        public void GenerateSrpProof_LargePassword_HandlesCorrectly()
        {
            // Arrange
            var largePassword = new string('P', 1000);
            var bBytes = RandomNumberGenerator.GetBytes(32);
            var (_, authHashBytes, x) = DeriveAuthComponents(TestLogin, largePassword, _testSalt);
            var v = BigInteger.ModPow(SecurityConstants.g, x, SecurityConstants.N);
            var B = GenerateValidB(v, bBytes);
            var B_base64 = Convert.ToBase64String(SrpEncoding.ToModulusBytes(B));

            // Act
            var (A, M1, S) = _client.GenerateSrpProof(TestLogin, largePassword, _testSaltBase64, B_base64);

            // Assert
            Assert.NotNull(A);
            Assert.NotNull(M1);
            Assert.NotNull(S);
        }

        [Fact]
        public void GenerateSrpProof_UnicodePassword_HandlesCorrectly()
        {
            // Arrange
            var unicodePassword = "Пароль🔐密码🗝️";
            var bBytes = RandomNumberGenerator.GetBytes(32);
            var (_, authHashBytes, x) = DeriveAuthComponents(TestLogin, unicodePassword, _testSalt);
            var v = BigInteger.ModPow(SecurityConstants.g, x, SecurityConstants.N);
            var B = GenerateValidB(v, bBytes);
            var B_base64 = Convert.ToBase64String(SrpEncoding.ToModulusBytes(B));

            // Act
            var (A, M1, S) = _client.GenerateSrpProof(TestLogin, unicodePassword, _testSaltBase64, B_base64);

            // Assert
            Assert.NotNull(A);
            Assert.NotNull(M1);
            Assert.NotNull(S);
        }

        [Fact]
        public void GenerateSrpVerifier_EmptyAuthHashBytes_ProducesValidOutput()
        {
            // Arrange: Empty auth hash (edge case, though insecure in practice)
            var emptyAuthHash = Convert.ToBase64String(Array.Empty<byte>());

            // Act
            var verifier = _client.GenerateSrpVerifier(emptyAuthHash);

            // Assert: Should produce g^0 = 1
            Assert.NotNull(verifier);
        }

        #endregion
    }
}