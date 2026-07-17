using System.Security.Cryptography;
using Crossdyne.Security.Configuration;
using Crossdyne.Security.Cryptography;
using Crossdyne.Security.Srp.Client;
using Crossdyne.Security.Srp.Server;
using Crossdyne.Security.Tests.Helpers;

namespace Crossdyne.Security.Tests
{
    /// <summary>
    /// End-to-end integration tests for the complete SRP authentication flow.
    /// Simulates real client-server interaction.
    /// </summary>
    public class SrpIntegrationTests
    {
        private readonly SrpClientService _client;
        private readonly SrpServerService _server;
        private readonly KeyDerivationService _kdf;
        private const string TestLogin = "alice@quantropic.ru";
        private const string TestPassword = "Str0ng!P@ssw0rd#2024";
        private readonly byte[] _salt;
        private readonly CryptoVersion CryptoVersion = CryptoVersion.V1;

        public SrpIntegrationTests()
        {
            _client = new SrpClientService();
            _server = new SrpServerService();
            _kdf = new KeyDerivationService();
            _salt = RandomNumberGenerator.GetBytes(32);
        }

        [Fact]
        public void FullSrpFlow_ValidCredentials_AuthenticationSucceeds()
        {
            // === PHASE 1: Registration ===
            var context = SrpHelper.GetSrpContext();
            var authHash = _kdf.DeriveAuthHashForSrp(TestLogin, TestPassword, _salt, context.HashAlgorithmName, CryptoVersion);
            var verifierBase64 = _client.GenerateSrpVerifier(Convert.ToBase64String(authHash), context);
            var verifierBytes = Convert.FromBase64String(verifierBase64);
            var storedVerifier = verifierBytes;

            // === PHASE 2: Authentication Challenge ===
            var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier, _salt,context);
            var B_base64 = challenge.PublicKeyB;
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');

            // === PHASE 3: Client Proof Generation ===
            // Было: var (A, M1, S) = _client.GenerateSrpProof(...)
            var (A, M1, sessionKeyK) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64, Convert.ToBase64String(B_base64), context, CryptoVersion);

            // === PHASE 4: Server Verification ===
            var M2 = _server.VerifySrpProof(challenge, A, M1, context);

            // === PHASE 5: Client Server Authentication ===
            var serverAuthenticated = _client.VerifyServerM2(A, M1, sessionKeyK, M2, context);

            // === ASSERTIONS ===
            Assert.True(serverAuthenticated, "Server authentication should succeed with valid credentials");

            Assert.Equal(context.HashSize, sessionKeyK.Length);
        }

        [Fact]
        public void FullSrpFlow_WrongPassword_AuthenticationFails()
        {
            // === Registration with correct password ===
             var context = SrpHelper.GetSrpContext();
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _salt, CryptoVersion);
            var verifierBase64 = _client.GenerateSrpVerifier(authHash, context);
            var storedVerifier = Convert.FromBase64String(verifierBase64);

            // === Challenge ===
            var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier, _salt, context);
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');

            // === Client attempts with WRONG password ===
            var wrongPassword = "WrongP@ssw0rd!";
            var exception = Record.Exception(() =>
            {
                var (A, M1, _) = _client.GenerateSrpProof(TestLogin, wrongPassword, saltBase64, Convert.ToBase64String(challenge.PublicKeyB), context, CryptoVersion);
                _server.VerifySrpProof(challenge, A, M1, context); // Should throw
            });

            // === ASSERTION ===
            Assert.IsType<Exceptions.SrpVerificationException>(exception);
            Assert.Contains("Invalid password", exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void FullSrpFlow_TamperedChallenge_AuthenticationFails()
        {
            // === Registration ===
             var context = SrpHelper.GetSrpContext();
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _salt, CryptoVersion);
            var verifierBase64 = _client.GenerateSrpVerifier(authHash, context);
            var storedVerifier = Convert.FromBase64String(verifierBase64);

            // === Challenge ===
            var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier, _salt, context);
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');

            // === Tamper with B (server's public value) ===
            var B_bytes = Convert.FromBase64String(Convert.ToBase64String(challenge.PublicKeyB));
            B_bytes[0] ^= 0xFF; // Flip one bit
            var tamperedB = Convert.ToBase64String(B_bytes);

            // === Client generates proof with tampered B ===
            var (A, M1, _) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64, tamperedB, context, CryptoVersion);

            // === Server tries to verify with original challenge ===
            var exception = Record.Exception(() =>
                _server.VerifySrpProof(challenge, A, M1, context));

            // === ASSERTION ===
            Assert.IsType<Exceptions.SrpVerificationException>(exception);
        }

        [Fact]
        public void FullSrpFlow_MultipleSequentialAuthentications_Succeeds()
        {
            // === Registration ===
             var context = SrpHelper.GetSrpContext();
            var authHash = _kdf.DeriveAuthHashForSrp(TestLogin, TestPassword, _salt, context.HashAlgorithmName, CryptoVersion);
            var verifierBase64 = _client.GenerateSrpVerifier(Convert.ToBase64String(authHash), context);
            var storedVerifier = Convert.FromBase64String(verifierBase64);
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');

            // === Multiple authentication rounds ===
            for (int i = 0; i < 5; i++)
            {
                // Server challenge (new random B each time)
                var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier, _salt, context);
                
                // Client proof
                var (A, M1, S) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64, Convert.ToBase64String(challenge.PublicKeyB), context, CryptoVersion);
                
                // Server verification
                var M2 = _server.VerifySrpProof(challenge, A, M1, context);
                
                // Client verifies server
                var authenticated = _client.VerifyServerM2(A, M1, S, M2, context);
                
                Assert.True(authenticated, $"Round {i + 1}: Server authentication should succeed");
            }
        }

        [Fact]
        public void FullSrpFlow_SessionKeyUsableForEncryption()
        {
            // === Full SRP flow to get session key ===
            var context = SrpHelper.GetSrpContext();
            var authHash = _kdf.DeriveAuthHashForSrp(TestLogin, TestPassword, _salt, context.HashAlgorithmName, CryptoVersion);
            var verifierBase64 = _client.GenerateSrpVerifier(Convert.ToBase64String(authHash), context);
            var storedVerifier = Convert.FromBase64String(verifierBase64);
            
            var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier, _salt, context);
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');
                        
            var (A, M1, sessionKeyK) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64, Convert.ToBase64String(challenge.PublicKeyB), context, CryptoVersion);
            var M2 = _server.VerifySrpProof(challenge, A, M1, context);
            var authenticated = _client.VerifyServerM2(A, M1, sessionKeyK, M2, context);
            
            Assert.True(authenticated);

            // === Use session key for AES-GCM encryption ===
            var cryptoService = new CryptoService();
            
            // Derive AES key from SRP session key (simplified: take first 32 bytes)
            var aesKey = new byte[SecurityConstants.KeySizeBytes];
            Buffer.BlockCopy(sessionKeyK, 0, aesKey, 0, Math.Min(sessionKeyK.Length, aesKey.Length));
            
            // Encrypt and decrypt test message
            const string secretMessage = "Confidential SRP-protected data 🔐";
            var encrypted = cryptoService.EncryptedData(secretMessage, aesKey);
            var decrypted = cryptoService.DecryptData<string>(encrypted, aesKey);
            
            Assert.Equal(secretMessage, decrypted);
        }

        [Fact]
        public async Task FullSrpFlow_ConcurrentAuthentications_DoesNotInterfere()
        {
            // === Registration ===
            var context = SrpHelper.GetSrpContext();
            var authHash = _kdf.DeriveAuthHashForSrp(TestLogin, TestPassword, _salt, context.HashAlgorithmName, CryptoVersion);
            var verifierBase64 = _client.GenerateSrpVerifier(Convert.ToBase64String(authHash), context);
            var storedVerifier = Convert.FromBase64String(verifierBase64);
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');

            // === Concurrent authentication attempts ===
            var tasks = new Task<bool>[10];
            for (int i = 0; i < 10; i++)
            {
                tasks[i] = Task.Run(() =>
                {
                    var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier, _salt, context);
                    var (A, M1, S) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64, Convert.ToBase64String(challenge.PublicKeyB), context, CryptoVersion);
                    var M2 = _server.VerifySrpProof(challenge, A, M1, context);
                    return _client.VerifyServerM2(A, M1, S, M2, context);
                });
            }

            var results = await Task.WhenAll(tasks);
            
            // All should succeed independently
            Assert.All(results, r => Assert.True(r));
        }
    }
}