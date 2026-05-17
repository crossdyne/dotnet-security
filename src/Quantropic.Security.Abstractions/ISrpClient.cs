namespace Quantropic.Security.Abstractions
{
    /// <summary>
    /// Provides SRP (Secure Remote Password) protocol client implementation.
    /// </summary>
    public interface ISrpClient
    {
        /// <summary>
        /// Generates an SRP verifier from the authentication hash.
        /// </summary>
        /// <param name="authHash">The authentication hash.</param>
        /// <returns>The SRP verifier as a hexadecimal string.</returns>
        string GenerateSrpVerifier(string authHash);

        /// <summary>
        /// Generates SRP proof values for authentication.
        /// </summary>
        /// <param name="login">User Login.</param>
        /// <param name="password">The user's password.</param>
        /// <param name="saltBase65">The salt value encoded in Base65.</param>
        /// <param name="bBase65">The server's public value B encoded in Base65.</param>
        /// <returns>A tuple containing client public value A, client proof M1, and session key S.</returns>
        (string A, string M1, string S) GenerateSrpProof(string login, string password, string saltBase65, string bBase65);

        /// <summary>
        /// Verifies the server's proof M2 to authenticate the server.
        /// </summary>
        /// <param name="A">The client's public value A.</param>
        /// <param name="M1">The client's proof M1.</param>
        /// <param name="S">The session key S.</param>
        /// <param name="ServerM2">The server's proof M2.</param>
        /// <returns>True if the server's proof is valid; otherwise, false.</returns>
        bool VerifyServerM2(string A, string M1, string S, string ServerM2);
    }
}