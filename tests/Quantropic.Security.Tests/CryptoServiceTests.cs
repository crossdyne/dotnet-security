using System.Text;
using System.Text.Json;
using Quantropic.Security.Configuration;
using Quantropic.Security.Cryptography;
using Quantropic.Security.Exceptions;

namespace Quantropic.Security.Tests.Cryptography
{
    public class CryptoServiceTests
    {
        private readonly CryptoService _service;
        private readonly byte[] _validKey;

        public CryptoServiceTests()
        {
            _service = new CryptoService();
            _validKey = _service.GenerateRandomBytes(SecurityConstants.KeySizeBytes);
        }

        #region Helper Methods

        private T Clone<T>(T obj) => JsonSerializer.Deserialize<T>(JsonSerializer.Serialize(obj))!;

        #endregion

        #region Basic Encryption/Decryption Tests

        [Fact]
        public void EncryptDecrypt_String_RoundTripSuccessful()
        {
            const string original = "Hello, World! 🔐";

            var encrypted = _service.EncryptedData(original, _validKey);
            var decrypted = _service.DecryptData<string>(encrypted, _validKey);

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

            var encrypted = _service.EncryptedData(original, _validKey);
            var decrypted = _service.DecryptData<TestUser>(encrypted, _validKey);

            Assert.NotNull(decrypted);
            Assert.Equal(original.Id, decrypted!.Id);
            Assert.Equal(original.Name, decrypted.Name);
            Assert.Equal(original.Email, decrypted.Email);
            Assert.Equal(original.Roles, decrypted.Roles);
            Assert.NotNull(decrypted.Metadata);
            Assert.Equal(original.Metadata.Created, decrypted.Metadata.Created);
            Assert.Equal(original.Metadata.Verified, decrypted.Metadata.Verified);
        }

        [Fact]
        public void EncryptDecrypt_Collection_RoundTripSuccessful()
        {
            var original = new[]
            {
                new { Id = 1, Value = "First" },
                new { Id = 2, Value = "Second" },
                new { Id = 3, Value = "Third" }
            };

            var encrypted = _service.EncryptedData(original, _validKey);
            var decrypted = _service.DecryptData<object[]>(encrypted, _validKey);

            Assert.NotNull(decrypted);
            Assert.Equal(3, decrypted?.Length);
        }

        [Fact]
        public void EncryptDecrypt_NullValue_HandlesCorrectly()
        {
            string? original = null;

            var encrypted = _service.EncryptedData(original, _validKey);
            var decrypted = _service.DecryptData<string?>(encrypted, _validKey);

            Assert.Null(decrypted);
        }

        [Fact]
        public void EncryptDecrypt_EmptyObject_HandlesCorrectly()
        {
            var original = new EmptyDto();

            var encrypted = _service.EncryptedData(original, _validKey);
            var decrypted = _service.DecryptData<EmptyDto>(encrypted, _validKey);

            Assert.NotNull(decrypted);
        }

        #endregion

        #region Key Validation Tests

        [Fact]
        public void EncryptedData_KeyTooShort_ThrowsInvalidKeyException()
        {
            var shortKey = new byte[16]; // 128-bit, not 256

            Assert.Throws<InvalidKeyException>(() => _service.EncryptedData("test", shortKey));
        }

        [Fact]
        public void EncryptedData_KeyTooLong_ThrowsInvalidKeyException()
        {
            var longKey = new byte[64]; // 512-bit

            Assert.Throws<InvalidKeyException>(() => _service.EncryptedData("test", longKey));
        }

        [Fact]
        public void EncryptedData_NullKey_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() => _service.EncryptedData("test", null!));
        }

        [Fact]
        public void DecryptData_NullKey_ThrowsArgumentNullException()
        {
            var encrypted = _service.EncryptedData("test", _validKey);

            Assert.Throws<ArgumentNullException>(() => 
                _service.DecryptData<string>(encrypted, null!));
        }

        [Fact]
        public void DecryptData_WrongKey_ThrowsDecryptionException()
        {
            var original = "Secret message";
            var encrypted = _service.EncryptedData(original, _validKey);
            var wrongKey = _service.GenerateRandomBytes(SecurityConstants.KeySizeBytes);

            Assert.Throws<DecryptionException>(() => _service.DecryptData<string>(encrypted, wrongKey));
        }

        #endregion

        #region Input Validation Tests

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void DecryptData_InvalidEncryptedString_ThrowsArgumentException(string? invalidInput)
        {
            Assert.Throws<ArgumentException>(() => _service.DecryptData<string>(invalidInput!, _validKey));
        }

        [Fact]
        public void DecryptData_InvalidBase64_ThrowsArgumentException()
        {
            Assert.Throws<ArgumentException>(() => _service.DecryptData<string>("!@#InvalidBase64$$$", _validKey));
        }

        [Fact]
        public void DecryptData_TooShortData_ThrowsDecryptionException()
        {
            var tooShort = Convert.ToBase64String(new byte[5]); // Way too short

            Assert.Throws<DecryptionException>(() =>  _service.DecryptData<string>(tooShort, _validKey));
        }

        [Fact]
        public void DecryptData_CorruptedData_ThrowsDecryptionException()
        {
            var original = "Important data";
            var encrypted = _service.EncryptedData(original, _validKey);
            var encryptedBytes = Convert.FromBase64String(encrypted);
            
            // Corrupt one byte in the middle (ciphertext)
            encryptedBytes[encryptedBytes.Length / 2] ^= 0xFF;
            var corrupted = Convert.ToBase64String(encryptedBytes);

            Assert.Throws<DecryptionException>(() => _service.DecryptData<string>(corrupted, _validKey));
        }

        [Fact]
        public void DecryptData_TamperedNonce_ThrowsDecryptionException()
        {
            var original = "Important data";
            var encrypted = _service.EncryptedData(original, _validKey);
            var encryptedBytes = Convert.FromBase64String(encrypted);
            
            // Corrupt nonce (first 12 bytes)
            encryptedBytes[0] ^= 0xFF;
            var tampered = Convert.ToBase64String(encryptedBytes);

            Assert.Throws<DecryptionException>(() =>  _service.DecryptData<string>(tampered, _validKey));
        }

        [Fact]
        public void DecryptData_TamperedTag_ThrowsDecryptionException()
        {
            var original = "Important data";
            var encrypted = _service.EncryptedData(original, _validKey);
            var encryptedBytes = Convert.FromBase64String(encrypted);
            
            encryptedBytes[^1] ^= 0xFF;
            var tampered = Convert.ToBase64String(encryptedBytes);

            Assert.Throws<DecryptionException>(() => _service.DecryptData<string>(tampered, _validKey));
        }

        #endregion

        #region CryptoOptions Tests

        [Fact]
        public void EncryptedData_WithCustomOptions_UsesSpecifiedConfiguration()
        {
            var options = CryptoOptions.Create()
                .WithTagSize(14)
                .WithAssociatedData("context:user:123")
                .Build();

            const string original = "Protected data";

            var encrypted = _service.EncryptedData(original, _validKey, options);
            var decrypted = _service.DecryptData<string>(encrypted, _validKey, options);

            Assert.Equal(original, decrypted);
        }

        [Fact]
        public void EncryptedData_WithNullOptions_UsesDefaults()
        {
            const string original = "Test";

            var encrypted1 = _service.EncryptedData(original, _validKey, options: null);
            var encrypted2 = _service.EncryptedData(original, _validKey);

            // Both should work (output differs due to random nonce, but both valid)
            var decrypted1 = _service.DecryptData<string>(encrypted1, _validKey);
            var decrypted2 = _service.DecryptData<string>(encrypted2, _validKey);

            Assert.Equal(original, decrypted1);
            Assert.Equal(original, decrypted2);
        }

        [Fact]
        public void EncryptedData_WithCustomIterations_AppliesConfiguration()
        {
            // Note: PBKDF2 iterations don't affect AES-GCM directly in this service,
            // but the overload should still accept and pass through the parameter.

            const string original = "Test";

            var encrypted = _service.EncryptedData(original, _validKey, pbkdf2Iterations: 700_000);
            var decrypted = _service.DecryptData<string>(encrypted, _validKey);

            Assert.Equal(original, decrypted);
        }

        [Fact]
        public void DecryptData_WithMismatchedOptions_ThrowsDecryptionException()
        {
            const string original = "Secret";
            var encryptOptions = CryptoOptions.Create().WithTagSize(14).Build();
            var decryptOptions = CryptoOptions.Create().WithTagSize(16).Build(); // Different!
            
            var encrypted = _service.EncryptedData(original, _validKey, encryptOptions);

            // Tag size mismatch should cause authentication failure
            Assert.Throws<DecryptionException>(() => _service.DecryptData<string>(encrypted, _validKey, decryptOptions));
        }

        [Fact]
        public void EncryptDecrypt_WithAssociatedData_SameAADRequired()
        {
            const string original = "Confidential";
            var aad = Encoding.UTF8.GetBytes("user:42:session:abc");
            var options = CryptoOptions.Create().WithAssociatedData(aad).Build();
            
            var encrypted = _service.EncryptedData(original, _validKey, options);

            // Act: Decrypt with same AAD - should succeed
            var decrypted = _service.DecryptData<string>(encrypted, _validKey, options);

            Assert.Equal(original, decrypted);

            // Act: Decrypt with different AAD - should fail
            var wrongOptions = CryptoOptions.Create()
                .WithAssociatedData("user:42:session:xyz")
                .Build();
            
            Assert.Throws<DecryptionException>(() => _service.DecryptData<string>(encrypted, _validKey, wrongOptions));
        }

        [Fact]
        public void EncryptDecrypt_WithoutAssociatedData_WithAADOptions_Throws()
        {
            const string original = "Data";
            var encrypted = _service.EncryptedData(original, _validKey); // No AAD
            
            var optionsWithAad = CryptoOptions.Create()
                .WithAssociatedData("some-aad")
                .Build();

            // Decrypting data without AAD using options with AAD should fail
            Assert.Throws<DecryptionException>(() => _service.DecryptData<string>(encrypted, _validKey, optionsWithAad));
        }

        #endregion

        #region Determinism & Randomness Tests

        [Fact]
        public void Encrypt_SameInput_ProducesDifferentOutput()
        {
            const string original = "Same message";

            var encrypted1 = _service.EncryptedData(original, _validKey);
            var encrypted2 = _service.EncryptedData(original, _validKey);

            // Nonce is random, so outputs should differ
            Assert.NotEqual(encrypted1, encrypted2);
            
            // But both should decrypt to the same value
            Assert.Equal(original, _service.DecryptData<string>(encrypted1, _validKey));
            Assert.Equal(original, _service.DecryptData<string>(encrypted2, _validKey));
        }

        [Fact]
        public void Encrypt_OutputIsValidBase64()
        {
            const string original = "Test";

            var encrypted = _service.EncryptedData(original, _validKey);

            // Should not throw
            var bytes = Convert.FromBase64String(encrypted);
            Assert.True(bytes.Length > 0);
        }

        [Fact]
        public void Encrypt_OutputContains_Nonce_Ciphertext_Tag()
        {
            const string original = "Test";
            var options = CryptoOptions.Default;

            var encrypted = _service.EncryptedData(original, _validKey, options);
            var bytes = Convert.FromBase64String(encrypted);

            var expectedLength = options.NonceSize + original.Length /*approx*/ + options.TagSize;
            Assert.True(bytes.Length >= options.NonceSize + options.TagSize);
            Assert.True(bytes.Length <= expectedLength + 100); // Allow for JSON overhead
        }

        #endregion

        #region Edge Cases & Unicode

        [Fact]
        public void EncryptDecrypt_UnicodeContent_HandlesCorrectly()
        {
            const string original = "Пароль 🔐 密码 🗝️ emoji 🎉";

            var encrypted = _service.EncryptedData(original, _validKey);
            var decrypted = _service.DecryptData<string>(encrypted, _validKey);

            Assert.Equal(original, decrypted);
        }

        [Fact]
        public void EncryptDecrypt_VeryLongString_HandlesCorrectly()
        {
            var original = new string('X', 100_000); // 100KB string

            var encrypted = _service.EncryptedData(original, _validKey);
            var decrypted = _service.DecryptData<string>(encrypted, _validKey);

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

            var encrypted = _service.EncryptedData(original, _validKey);
            var decrypted = _service.DecryptData<NestedDto>(encrypted, _validKey);

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

            var encrypted = _service.EncryptedData(original, _validKey);
            var decrypted = _service.DecryptData<TestUser>(encrypted, _validKey);

            Assert.NotNull(decrypted);
            Assert.Equal(original.Id, decrypted!.Id);
            Assert.Null(decrypted.Name);
        }

        #endregion

        #region GenerateRandomBytes Tests

        [Fact]
        public void GenerateRandomBytes_DefaultLength_Returns32Bytes()
        {
            var bytes = _service.GenerateRandomBytes();

            Assert.Equal(SecurityConstants.KeySizeBytes, bytes.Length);
        }

        [Fact]
        public void GenerateRandomBytes_CustomLength_ReturnsSpecifiedLength()
        {
            var bytes = _service.GenerateRandomBytes(64);

            Assert.Equal(64, bytes.Length);
        }

        [Fact]
        public void GenerateRandomBytes_MultipleCalls_ProducesDifferentValues()
        {
            var bytes1 = _service.GenerateRandomBytes(32);
            var bytes2 = _service.GenerateRandomBytes(32);

            Assert.False(bytes1.SequenceEqual(bytes2));
        }

        [Fact]
        public void GenerateRandomBytes_ZeroLength_ReturnsEmptyArray()
        {
            var bytes = _service.GenerateRandomBytes(0);

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
            var encrypted = _service.EncryptedData(original, _validKey);

            var decrypted = _service.DecryptData<string>(encrypted, _validKey);

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
            var encrypted = _service.EncryptedData(original, _validKey);

            var decrypted = _service.DecryptData<string>(encrypted, _validKey);

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
                _service.EncryptedData("test", shortKey));

            Assert.Contains("Key must be", exception.Message);
            Assert.Contains("bytes for AES-256", exception.Message);
        }

        [Fact]
        public void DecryptData_InvalidBase64_ExceptionHasInnerException()
        {
            var exception = Assert.Throws<ArgumentException>(() => _service.DecryptData<string>("!@#invalid$$$", _validKey));

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