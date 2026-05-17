using Quantropic.Security.Configuration;
using Quantropic.Security.Cryptography;
using Quantropic.Security.Exceptions;

namespace Quantropic.Security.Tests.Integration
{
    public class CryptoServiceIntegrationTests
    {
        private readonly CryptoService _service;

        public CryptoServiceIntegrationTests()
        {
            _service = new CryptoService();
        }

        [Fact]
        public void UserCredentials_EncryptDecrypt_RoundTrip()
        {
            // Scenario: Storing user credentials securely
            var credentials = new UserCredentials
            {
                Username = "alice@company.com",
                PasswordHash = "pbkdf2_sha256$...",
                RefreshToken = Guid.NewGuid().ToString(),
                ExpiresAt = DateTime.UtcNow.AddHours(24)
            };

            var key = _service.GenerateRandomBytes(SecurityConstants.KeySizeBytes);
            
            var encrypted = _service.EncryptedData(credentials, key);
            var decrypted = _service.DecryptData<UserCredentials>(encrypted, key);

            Assert.Equal(credentials.Username, decrypted?.Username);
            Assert.Equal(credentials.PasswordHash, decrypted?.PasswordHash);
            Assert.Equal(credentials.RefreshToken, decrypted?.RefreshToken);
            Assert.Equal(credentials.ExpiresAt, decrypted?.ExpiresAt);
        }

        [Fact]
        public void ConfigurationStore_MultipleItems_EncryptDecrypt()
        {
            // Scenario: Encrypting multiple configuration items
            var config = new Dictionary<string, string>
            {
                ["DbConnectionString"] = "Server=prod;Database=app;User=sa;Password=Secret123!",
                ["ApiKey"] = "sk-live-abcdef123456",
                ["WebhookSecret"] = "whsec_xyz789"
            };

            var key = _service.GenerateRandomBytes(SecurityConstants.KeySizeBytes);
            var aad = System.Text.Encoding.UTF8.GetBytes("env:production");
            var options = CryptoOptions.Create().WithAssociatedData(aad).Build();

            var encrypted = _service.EncryptedData(config, key, options);
            var decrypted = _service.DecryptData<Dictionary<string, string>>(encrypted, key, options);

            Assert.Equal(config.Count, decrypted?.Count);
            Assert.Equal(config["DbConnectionString"], decrypted?["DbConnectionString"]);
            Assert.Equal(config["ApiKey"], decrypted?["ApiKey"]);
        }

        [Fact]
        public void ConcurrentEncryption_DifferentKeys_Isolated()
        {
            // Scenario: Multiple users with different keys
            var users = new[]
            {
                new { Name = "Alice", Data = "Alice's secret" },
                new { Name = "Bob", Data = "Bob's secret" },
                new { Name = "Charlie", Data = "Charlie's secret" }
            };

            var encryptedItems = users.Select(u => 
            {
                var key = _service.GenerateRandomBytes(SecurityConstants.KeySizeBytes);
                return new
                {
                    u.Name,
                    u.Data,
                    Key = key,
                    Encrypted = _service.EncryptedData(u.Data, key) 
                };
            }).ToList();

            // Each user can only decrypt their own data
            foreach (var item in encryptedItems)
            {
                var decrypted = _service.DecryptData<string>(item.Encrypted, item.Key);
                Assert.Equal(item.Data, decrypted);
            }

            // Wrong key fails — checking the key isolation
            foreach (var item in encryptedItems)
            {
                var wrongKey = _service.GenerateRandomBytes(SecurityConstants.KeySizeBytes);
                Assert.Throws<DecryptionException>(() => 
                    _service.DecryptData<string>(item.Encrypted, wrongKey));
            }
        }

        [Fact]
        public async Task LargePayload_EncryptDecrypt_PerformanceAcceptable()
        {
            // Scenario: Encrypting large JSON payloads
            var largeData = Enumerable.Range(0, 10_000)
                .Select(i => new { Id = i, Timestamp = DateTime.UtcNow, Payload = new string('X', 100) })
                .ToList();

            var key = _service.GenerateRandomBytes(SecurityConstants.KeySizeBytes);

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var encrypted = _service.EncryptedData(largeData, key);
            var encryptTime = stopwatch.ElapsedMilliseconds;

            stopwatch.Restart();
            var decrypted = _service.DecryptData<List<object>>(encrypted, key);
            var decryptTime = stopwatch.ElapsedMilliseconds;

            Assert.NotNull(decrypted);
            Assert.Equal(largeData.Count, decrypted?.Count);
            
            // Performance assertion: should complete in reasonable time (< 5 seconds each)
            Assert.True(encryptTime < 5000, $"Encryption took {encryptTime}ms");
            Assert.True(decryptTime < 5000, $"Decryption took {decryptTime}ms");
        }

        private class UserCredentials
        {
            public string? Username { get; set; }
            public string? PasswordHash { get; set; }
            public string? RefreshToken { get; set; }
            public DateTime ExpiresAt { get; set; }
        }
    }
}