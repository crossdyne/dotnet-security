using System.Security.Cryptography;
using Quantropic.Security.Configuration;
using Quantropic.Security.Cryptography;
using Quantropic.Security.Srp.Client;
using Quantropic.Security.Srp.Server;

namespace Quantropic.Security.Tests.Srp.Integration
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
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _salt);
            var verifierBase64 = _client.GenerateSrpVerifier(authHash);
            var verifierBytes = Convert.FromBase64String(verifierBase64);
            
            // Server: Store verifier (simulated)
            var storedVerifier = verifierBytes;

            // === PHASE 2: Authentication Challenge ===
            // Server: Generate challenge
            var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier);
            var B_base64 = challenge.PublicKeyB;
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');

            // === PHASE 3: Client Proof Generation ===
            // Client: Generate A, M1, S
            var (A, M1, S) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64, B_base64);

            // === PHASE 4: Server Verification ===
            // Server: Verify M1 and generate M2
            var M2 = _server.VerifySrpProof(challenge, A, M1);

            // === PHASE 5: Client Server Authentication ===
            // Client: Verify M2
            var serverAuthenticated = _client.VerifyServerM2(A, M1, S, M2);

            // === ASSERTIONS ===
            Assert.True(serverAuthenticated, "Server authentication should succeed with valid credentials");
            
            // Session key S should be usable for further encryption
            var sessionKeyBytes = Convert.FromBase64String(S);
            Assert.Equal(SecurityConstants.ModulusSize, sessionKeyBytes.Length);
        }

        [Fact]
        public void FullSrpFlow_WrongPassword_AuthenticationFails()
        {
            // === Registration with correct password ===
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _salt);
            var verifierBase64 = _client.GenerateSrpVerifier(authHash);
            var storedVerifier = Convert.FromBase64String(verifierBase64);

            // === Challenge ===
            var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier);
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');

            // === Client attempts with WRONG password ===
            var wrongPassword = "WrongP@ssw0rd!";
            var exception = Record.Exception(() =>
            {
                var (A, M1, _) = _client.GenerateSrpProof(TestLogin, wrongPassword, saltBase64, challenge.PublicKeyB);
                _server.VerifySrpProof(challenge, A, M1); // Should throw
            });

            // === ASSERTION ===
            Assert.IsType<Quantropic.Security.Exceptions.SrpVerificationException>(exception);
            Assert.Contains("Invalid password", exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void FullSrpFlow_TamperedChallenge_AuthenticationFails()
        {
            // === Registration ===
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _salt);
            var verifierBase64 = _client.GenerateSrpVerifier(authHash);
            var storedVerifier = Convert.FromBase64String(verifierBase64);

            // === Challenge ===
            var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier);
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');

            // === Tamper with B (server's public value) ===
            var B_bytes = Convert.FromBase64String(challenge.PublicKeyB);
            B_bytes[0] ^= 0xFF; // Flip one bit
            var tamperedB = Convert.ToBase64String(B_bytes);

            // === Client generates proof with tampered B ===
            var (A, M1, _) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64, tamperedB);

            // === Server tries to verify with original challenge ===
            var exception = Record.Exception(() =>
                _server.VerifySrpProof(challenge, A, M1));

            // === ASSERTION ===
            Assert.IsType<Quantropic.Security.Exceptions.SrpVerificationException>(exception);
        }

        [Fact]
        public void FullSrpFlow_MultipleSequentialAuthentications_Succeeds()
        {
            // === Registration ===
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _salt);
            var verifierBase64 = _client.GenerateSrpVerifier(authHash);
            var storedVerifier = Convert.FromBase64String(verifierBase64);
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');

            // === Multiple authentication rounds ===
            for (int i = 0; i < 5; i++)
            {
                // Server challenge (new random B each time)
                var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier);
                
                // Client proof
                var (A, M1, S) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64, challenge.PublicKeyB);
                
                // Server verification
                var M2 = _server.VerifySrpProof(challenge, A, M1);
                
                // Client verifies server
                var authenticated = _client.VerifyServerM2(A, M1, S, M2);
                
                Assert.True(authenticated, $"Round {i + 1}: Server authentication should succeed");
            }
        }

        [Fact]
        public void FullSrpFlow_SessionKeyUsableForEncryption()
        {
            // === Full SRP flow to get session key ===
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _salt);
            var verifierBase64 = _client.GenerateSrpVerifier(authHash);
            var storedVerifier = Convert.FromBase64String(verifierBase64);
            
            var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier);
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');
            
            var (A, M1, S) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64, challenge.PublicKeyB);
            var M2 = _server.VerifySrpProof(challenge, A, M1);
            var authenticated = _client.VerifyServerM2(A, M1, S, M2);
            
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
            var (_, authHash) = _kdf.DeriveKeysFromPassword(TestLogin, TestPassword, _salt);
            var verifierBase64 = _client.GenerateSrpVerifier(authHash);
            var storedVerifier = Convert.FromBase64String(verifierBase64);
            var saltBase64 = Convert.ToBase64String(_salt).Replace('+', '-').Replace('/', '_');

            // === Concurrent authentication attempts ===
            var tasks = new Task<bool>[10];
            for (int i = 0; i < 10; i++)
            {
                tasks[i] = Task.Run(() =>
                {
                    var challenge = _server.GetSrpChallenge(TestLogin, storedVerifier);
                    var (A, M1, S) = _client.GenerateSrpProof(TestLogin, TestPassword, saltBase64, challenge.PublicKeyB);
                    var M2 = _server.VerifySrpProof(challenge, A, M1);
                    return _client.VerifyServerM2(A, M1, S, M2);
                });
            }

            var results = await Task.WhenAll(tasks);
            
            // All should succeed independently
            Assert.All(results, r => Assert.True(r));
        }
    }
}