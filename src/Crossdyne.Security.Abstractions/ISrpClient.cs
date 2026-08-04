using Crossdyne.Security.Configuration;

namespace Crossdyne.Security.Abstractions
{
    /// <summary>
    /// Client-side SRP-6a operations: verifier creation, proof generation, server M2 verification.
    /// </summary>
    public interface ISrpClient
    {
        /// <summary>
        /// Generates SRP verifier v = g^x mod N from authentication hash.
        /// </summary>
        /// <param name="authHash">Authentication hash (standard Base64).</param>
        /// <param name="srpGroup">SRP group.</param>
        /// <returns>Verifier as Base64 string.</returns>
        /// <exception cref="FormatException"><paramref name="authHash"/> is not a valid Base64 string.</exception>
        string GenerateSrpVerifier(string authHash, SrpGroup srpGroup);

        /// <summary>
        /// Generates client proof (A, M1, session key K) from server challenge.
        /// </summary>
        /// <param name="login">User login.</param>
        /// <param name="authHashBytes">PasswordHash Bytes.</param>
        /// <param name="saltBase64">Server salt (standard Base64).</param>
        /// <param name="bBase64">Server public ephemeral B (standard Base64).</param>
        /// <param name="srpGroup">SRP group.</param>
        /// <returns>
        /// Tuple where <c>A</c> and <c>M1</c> are standard Base64 strings, 
        /// and <c>SessionKeyK</c> is the raw session key bytes.
        /// </returns>
        /// <exception cref="ArgumentException"><paramref name="login"/> or <paramref name="authHashBytes"/> is null or empty.</exception>
        /// <exception cref="Exceptions.InvalidKeyException">Salt is null or too short.</exception>
        /// <exception cref="Exceptions.SecurityException">Invalid server public key or shared secret is zero.</exception>
        /// <exception cref="Exceptions.SrpVerificationException">Error calculating parameter u.</exception>
        (string A, string M1, byte[] SessionKeyK) GenerateSrpProof(string login, byte[] authHashBytes, string saltBase64, string bBase64, SrpGroup srpGroup);

        /// <summary>
        /// Verifies the server proof M2.
        /// </summary>
        /// <param name="A">Client public A (standard Base64).</param>
        /// <param name="M1">Client proof M1 (standard Base64).</param>
        /// <param name="SessionKeyK">Session key K as raw bytes.</param>
        /// <param name="ServerM2">Server proof M2 (standard Base64).</param>
        /// <param name="srpGroup">SRP group.</param>
        /// <returns><see langword="true"/> if server proof is valid; otherwise, <see langword="false"/>.</returns>
        bool VerifyServerM2(string A, string M1, byte[] SessionKeyK, string ServerM2, SrpGroup srpGroup);
    }
}