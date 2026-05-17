using System.Numerics;
using System.Security.Cryptography;
using Crossdyne.Security.Abstractions;
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
            // Client: Derive auth hash and generate verifier
            var context = SrpHelper.GetSrpContext();
            var authHash = _kdf.DeriveAuthHashForSrp(TestLogin, TestPassword, _salt, context.HashAlgorithmName);
            var verifierBase64 = _client.GenerateSrpVerifier(Convert.ToBase64String(authHash), context);
            var verifierBytes = Convert.FromBase64String(verifierBase64);
            
            // Server: Store verifier (simulated)
            var storedVerifier = verifierBytes;

            // === PHASE 2: Authentication Challenge ===
            // Server: Generate challenge
            var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier, context);
            var B_base64 = challenge.PublicKeyB;
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');

            // === PHASE 3: Client Proof Generation ===
            // Client: Generate A, M1, S
            var (A, M1, S) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64, B_base64, context);

            // === PHASE 4: Server Verification ===
            // Server: Verify M1 and generate M2
            var M2 = _server.VerifySrpProof(challenge, A, M1, context);

            // === PHASE 5: Client Server Authentication ===
            // Client: Verify M2
            var serverAuthenticated = _client.VerifyServerM2(A, M1, S, M2, context);

            // === ASSERTIONS ===
            Assert.True(serverAuthenticated, "Server authentication should succeed with valid credentials");
            
            // Session key S should be usable for further encryption
            var sessionKeyBytes = Convert.FromBase64String(S);
            Assert.Equal(context.ModulusSize, sessionKeyBytes.Length);
        }

        [Fact]
        public void FullSrpFlow_WrongPassword_AuthenticationFails()
        {
            // === Registration with correct password ===
             var context = SrpHelper.GetSrpContext();
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _salt);
            var verifierBase64 = _client.GenerateSrpVerifier(authHash, context);
            var storedVerifier = Convert.FromBase64String(verifierBase64);

            // === Challenge ===
            var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier, context);
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');

            // === Client attempts with WRONG password ===
            var wrongPassword = "WrongP@ssw0rd!";
            var exception = Record.Exception(() =>
            {
                var (A, M1, _) = _client.GenerateSrpProof(TestLogin, wrongPassword, saltBase64, challenge.PublicKeyB, context);
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
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _salt);
            var verifierBase64 = _client.GenerateSrpVerifier(authHash, context);
            var storedVerifier = Convert.FromBase64String(verifierBase64);

            // === Challenge ===
            var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier, context);
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');

            // === Tamper with B (server's public value) ===
            var B_bytes = Convert.FromBase64String(challenge.PublicKeyB);
            B_bytes[0] ^= 0xFF; // Flip one bit
            var tamperedB = Convert.ToBase64String(B_bytes);

            // === Client generates proof with tampered B ===
            var (A, M1, _) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64, tamperedB, context);

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
            var authHash = _kdf.DeriveAuthHashForSrp(TestLogin, TestPassword, _salt, context.HashAlgorithmName);
            var verifierBase64 = _client.GenerateSrpVerifier(Convert.ToBase64String(authHash), context);
            var storedVerifier = Convert.FromBase64String(verifierBase64);
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');

            // === Multiple authentication rounds ===
            for (int i = 0; i < 5; i++)
            {
                // Server challenge (new random B each time)
                var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier, context);
                
                // Client proof
                var (A, M1, S) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64, challenge.PublicKeyB, context);
                
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
            var authHash = _kdf.DeriveAuthHashForSrp(TestLogin, TestPassword, _salt, context.HashAlgorithmName);
            var verifierBase64 = _client.GenerateSrpVerifier(Convert.ToBase64String(authHash), context);
            var storedVerifier = Convert.FromBase64String(verifierBase64);
            
            var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier, context);
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');
            
            var (A, M1, S) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64, challenge.PublicKeyB, context);
            var M2 = _server.VerifySrpProof(challenge, A, M1, context);
            var authenticated = _client.VerifyServerM2(A, M1, S, M2, context);
            
            Assert.True(authenticated);

            // === Use session key for AES-GCM encryption ===
            var cryptoService = new CryptoService();
            
            // Derive AES key from SRP session key (simplified: take first 32 bytes)
            var S_bytes = Convert.FromBase64String(S);
            var aesKey = new byte[SecurityConstants.KeySizeBytes];
            Array.Copy(S_bytes, aesKey, SecurityConstants.KeySizeBytes);
            
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
            var authHash = _kdf.DeriveAuthHashForSrp(TestLogin, TestPassword, _salt, context.HashAlgorithmName);
            var verifierBase64 = _client.GenerateSrpVerifier(Convert.ToBase64String(authHash), context);
            var storedVerifier = Convert.FromBase64String(verifierBase64);
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');

            // === Concurrent authentication attempts ===
            var tasks = new Task<bool>[10];
            for (int i = 0; i < 10; i++)
            {
                tasks[i] = Task.Run(() =>
                {
                    var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier, context);
                    var (A, M1, S) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64, challenge.PublicKeyB, context);
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