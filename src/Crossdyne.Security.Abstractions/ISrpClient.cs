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
        /// <param name="ctx">SRP context.</param>
        /// <param name="authHash">Authentication hash (Base64).</param>
        /// <returns>Verifier as Base64 string.</returns>
        string GenerateSrpVerifier(string authHash, SrpContext ctx);

        /// <summary>
        /// Generates client proof (A, M1, S) from server challenge.
        /// </summary>
        /// <param name="ctx">SRP context.</param>
        /// <param name="login">User login.</param>
        /// <param name="password">Plaintext password.</param>
        /// <param name="saltBase64">Server salt (URL-safe Base64).</param>
        /// <param name="bBase64">Server public B (URL-safe Base64).</param>
        /// <returns>Tuple (A, M1, S) as Base64 strings.</returns>
        (string A, string M1, string S) GenerateSrpProof(string login, string password, string saltBase64, string bBase64, SrpContext ctx);

        /// <summary>
        /// Verifies the server proof M2.
        /// </summary>
        /// <param name="ctx">SRP context.</param>
        /// <param name="A">Client public A (Base64).</param>
        /// <param name="M1">Client proof M1 (Base64).</param>
        /// <param name="S">Session key S (Base64).</param>
        /// <param name="ServerM2">Server proof M2 (Base64).</param>
        /// <returns>True if server proof is valid.</returns>
        bool VerifyServerM2(string A, string M1, string S, string ServerM2, SrpContext ctx);
    }
}