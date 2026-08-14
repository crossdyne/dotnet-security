using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Configuration;
using Crossdyne.Security.Cryptography;
using Crossdyne.Security.Exceptions;

namespace Crossdyne.Security.Tests
{
    public class CryptoServiceTests
    {
        private readonly ICryptoService crypto = new CryptoService();
        private readonly byte[] validKey;

        public CryptoServiceTests()
        {
            validKey = crypto.GenerateRandomBytes(SecurityConstants.KeySizeBytes);
        }

        #region Encrypted

        [Fact]
        public void EncryptDecrypt_String_RoundTripSuccessful()
        {
            const string original = "Hello, World! 🔐";

            var encrypted = crypto.EncryptData(original, validKey);
            var decrypted = crypto.DecryptData<string>(encrypted, validKey);

            Assert.Equal(original, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_ComplexObject_RoundTripSuccessful()
        {
            var metadata = new UserMetadata 
            { 
                Created = DateTime.UtcNow, 
                Verified = true 
            };
            
            var original = new TestUser
            {
                Id = Guid.NewGuid(),
                Name = "Alice",
                Email = "alice@example.com",
                Roles = new[] { "admin", "user" },
                Metadata = metadata
            };

            var encrypted = crypto.EncryptData(original, validKey);
            var decrypted = crypto.DecryptData<TestUser>(encrypted, validKey);

            Assert.NotNull(decrypted);
            Assert.Equal(original.Id, decrypted!.Id);
            Assert.Equal(original.Name, decrypted.Name);
            Assert.Equal(original.Email, decrypted.Email);
            Assert.Equal(original.Roles, decrypted.Roles);
            Assert.NotNull(decrypted.Metadata);
            Assert.Equal(original.Metadata.Created, decrypted.Metadata.Created);
            Assert.Equal(original.Metadata.Verified, decrypted.Metadata.Verified);
        }

        #endregion

        
        #region Key Validation Tests

        [Fact]
        public void EncryptedData_KeyTooShort_ThrowsInvalidKeyException()
        {
            var shortKey = new byte[16]; // 128-bit, not 256

            Assert.Throws<InvalidKeyException>(() => crypto.EncryptData("test", shortKey));
        }

        [Fact]
        public void EncryptedData_KeyTooLong_ThrowsInvalidKeyException()
        {
            var longKey = new byte[64]; // 512-bit

            Assert.Throws<InvalidKeyException>(() => crypto.EncryptData("test", longKey));
        }

        [Fact]
        public void EncryptedData_NullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => crypto.EncryptData("test", null!));
        }

        [Fact]
        public void DecryptData_NullKey_ThrowsArgumentNullException()
        {
            var encrypted = crypto.EncryptData("test", validKey);

            Assert.Throws<ArgumentNullException>(() => 
                crypto.DecryptData<string>(encrypted, null!));
        }

        [Fact]
        public void DecryptData_WrongKey_ThrowsDecryptionException()
        {
            var original = "Secret message";
            var encrypted = crypto.EncryptData(original, validKey);
            var wrongKey = crypto.GenerateRandomBytes(SecurityConstants.KeySizeBytes);

            Assert.Throws<DecryptionException>(() => crypto.DecryptData<string>(encrypted, wrongKey));
        }

        #endregion

        #region Input Validation Tests

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void DecryptData_InvalidEncryptedString_ThrowsArgumentException(string? invalidInput)
        {
            Assert.Throws<ArgumentException>(() => crypto.DecryptData<string>(invalidInput!, validKey));
        }

        [Fact]
        public void DecryptData_InvalidBase64_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => crypto.DecryptData<string>("!@#InvalidBase64$$$", validKey));
        }

        [Fact]
        public void DecryptData_TooShortData_ThrowsSecurityException()
        {
            var tooShort = Convert.ToBase64String(new byte[5]); // Way too short

            Assert.Throws<SecurityException>(() =>  crypto.DecryptData<string>(tooShort, validKey));
        }

        [Fact]
        public void DecryptData_CorruptedData_ThrowsDecryptionException()
        {
            var original = "Important data";
            var encrypted = crypto.EncryptData(original, validKey);
            var encryptedBytes = Convert.FromBase64String(encrypted);
            
            // Corrupt one byte in the middle (ciphertext)
            encryptedBytes[encryptedBytes.Length / 2] ^= 0xFF;
            var corrupted = Convert.ToBase64String(encryptedBytes);

            Assert.Throws<DecryptionException>(() => crypto.DecryptData<string>(corrupted, validKey));
        }

        [Fact]
        public void DecryptData_TamperedTag_ThrowsDecryptionException()
        {
            var original = "Important data";
            var encrypted = crypto.EncryptData(original, validKey);
            var encryptedBytes = Convert.FromBase64String(encrypted);
            
            encryptedBytes[^1] ^= 0xFF;
            var tampered = Convert.ToBase64String(encryptedBytes);

            Assert.Throws<DecryptionException>(() => crypto.DecryptData<string>(tampered, validKey));
        }

        #endregion

        #region Determinism & Randomness Tests

        [Fact]
        public void Encrypt_SameInput_ProducesDifferentOutput()
        {
            const string original = "Same message";

            var encrypted1 = crypto.EncryptData(original, validKey);
            var encrypted2 = crypto.EncryptData(original, validKey);

            // Nonce is random, so outputs should differ
            Assert.NotEqual(encrypted1, encrypted2);
            
            // But both should decrypt to the same value
            Assert.Equal(original, crypto.DecryptData<string>(encrypted1, validKey));
            Assert.Equal(original, crypto.DecryptData<string>(encrypted2, validKey));
        }

        [Fact]
        public void Encrypt_OutputIsValidBase64()
        {
            const string original = "Test";

            var encrypted = crypto.EncryptData(original, validKey);

            // Should not throw
            var bytes = Convert.FromBase64String(encrypted);
            Assert.True(bytes.Length > 0);
        }

        #endregion

        #region Edge Cases & Unicode

        [Fact]
        public void EncryptDecrypt_UnicodeContent_HandlesCorrectly()
        {
            const string original = "Пароль 🔐 密码 🗝️ emoji 🎉";

            var encrypted = crypto.EncryptData(original, validKey);
            var decrypted = crypto.DecryptData<string>(encrypted, validKey);

            Assert.Equal(original, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_VeryLongString_HandlesCorrectly()
        {
            var original = new string('X', 100_000); // 100KB string

            var encrypted = crypto.EncryptData(original, validKey);
            var decrypted = crypto.DecryptData<string>(encrypted, validKey);

            Assert.Equal(original, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_DeeplyNestedObject_HandlesCorrectly()
        {
            var original = new NestedDto
            {
                Level1 = new Level1Dto
                {
                    Level2 = new Level2Dto
                    {
                        Value = "Deep value",
                        Items = new[] { 1, 2, 3 }
                    }
                }
            };

            var encrypted = crypto.EncryptData(original, validKey);
            var decrypted = crypto.DecryptData<NestedDto>(encrypted, validKey);

            Assert.NotNull(decrypted);
            Assert.Equal("Deep value", decrypted?.Level1?.Level2?.Value);
            Assert.Equal(new[] { 1, 2, 3 }, decrypted?.Level1?.Level2?.Items);
        }

        [Fact]
        public void EncryptDecrypt_NullableObject_WithNullProperties_HandlesCorrectly()
        {
            var original = new TestUser
            {
                Id = Guid.NewGuid(),
                Name = null,
                Email = null,
                Roles = null
            };

            var encrypted = crypto.EncryptData(original, validKey);
            var decrypted = crypto.DecryptData<TestUser>(encrypted, validKey);

            Assert.NotNull(decrypted);
            Assert.Equal(original.Id, decrypted!.Id);
            Assert.Null(decrypted.Name);
        }

        #endregion

        #region GenerateRandomBytes Tests

        [Fact]
        public void GenerateRandomBytes_DefaultLength_Returns32Bytes()
        {
            var bytes = crypto.GenerateRandomBytes();

            Assert.Equal(SecurityConstants.KeySizeBytes, bytes.Length);
        }

        [Fact]
        public void GenerateRandomBytes_CustomLength_ReturnsSpecifiedLength()
        {
            var bytes = crypto.GenerateRandomBytes(64);

            Assert.Equal(64, bytes.Length);
        }

        [Fact]
        public void GenerateRandomBytes_MultipleCalls_ProducesDifferentValues()
        {
            var bytes1 = crypto.GenerateRandomBytes(32);
            var bytes2 = crypto.GenerateRandomBytes(32);

            Assert.False(bytes1.SequenceEqual(bytes2));
        }

        [Fact]
        public void GenerateRandomBytes_ZeroLength_ReturnsEmptyArray()
        {
            var bytes = crypto.GenerateRandomBytes(0);

            Assert.Empty(bytes);
        }

        #endregion

        #region Memory Safety Tests (Indirect)

        [Fact]
        public void DecryptData_PlainBytesClearedAfterUse_IndirectVerification()
        {
            // We can't directly verify Array.Clear on internal buffers,
            // but we can verify that the method completes successfully
            // and doesn't leak sensitive data through exceptions.
            
            const string original = "Sensitive data";
            var encrypted = crypto.EncryptData(original, validKey);

            var decrypted = crypto.DecryptData<string>(encrypted, validKey);

            Assert.Equal(original, decrypted);
            // If plainBytes weren't cleared properly, it wouldn't affect output,
            // but the finally block ensures cleanup. Tested via code review.
        }

        #endregion

        #region Format Version Tests

        [Fact]
        public void DecryptData_LegacyFormat_Version0_Supported()
        {
            // The current implementation uses DecryptDataV0 which expects [Nonce][Ciphertext][Tag]
            // This test verifies the format is correctly parsed.
            
            const string original = "Legacy format test";
            var encrypted = crypto.EncryptData(original, validKey);

            var decrypted = crypto.DecryptData<string>(encrypted, validKey);

            Assert.Equal(original, decrypted);
        }

        #endregion

        #region Exception Message Tests

        [Fact]
        public void EncryptedData_InvalidKey_ExceptionMessageContainsExpectedText()
        {
            var shortKey = new byte[16];

            // Act
            var exception = Assert.Throws<InvalidKeyException>(() => 
                crypto.EncryptData("test", shortKey));

            Assert.Contains("Key must be", exception.Message);
            Assert.Contains("bytes for AES-256", exception.Message);
        }

        [Fact]
        public void DecryptData_InvalidBase64_ExceptionHasInnerException()
        {
            var exception = Assert.Throws<ArgumentException>(() => crypto.DecryptData<string>("!@#invalid$$$", validKey));

            Assert.Contains("Base64", exception.Message);
            Assert.NotNull(exception.InnerException);
            Assert.IsType<FormatException>(exception.InnerException);
        }

        #endregion

        #region Test DTOs

        private class UserMetadata
        {
            public DateTime Created { get; set; }
            public bool Verified { get; set; }
        }

        private class TestUser
        {
            public Guid Id { get; set; }
            public string? Name { get; set; }
            public string? Email { get; set; }
            public string[]? Roles { get; set; }
            public UserMetadata? Metadata { get; set; }
        }

        private class EmptyDto { }

        private class NestedDto
        {
            public Level1Dto? Level1 { get; set; }
        }

        private class Level1Dto
        {
            public Level2Dto? Level2 { get; set; }
        }

        private class Level2Dto
        {
            public string? Value { get; set; }
            public int[]? Items { get; set; }
        }

        #endregion
    }
}