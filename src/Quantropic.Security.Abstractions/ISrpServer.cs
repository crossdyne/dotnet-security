namespace Quantropic.Security.Abstractions
{
    /// <summary>
    /// Provides SRP (Secure Remote Password) protocol server implementation.
    /// </summary>
    public interface ISrpServer
    {
        /// <summary>
        /// Generates an SRP challenge for the client.
        /// </summary>
        /// <param name="login">The user's login identifier.</param>
        /// <param name="verifierBytes">The user's verifier bytes.</param>
        /// <returns>The SRP session state containing salt and server public value B.</returns>
        SrpSessionState GetSrpChallenge(string login, byte[] verifierBytes);

        /// <summary>
        /// Verifies the client's SRP proof and generates server proof M2.
        /// </summary>
        /// <param name="sessionState">The SRP session state.</param>
        /// <param name="a">The client's public value A.</param>
        /// <param name="m1">The client's proof M1.</param>
        /// <returns>The server's proof M2 as a hexadecimal string, or empty if verification fails.</returns>
        string VerifySrpProof(SrpSessionState sessionState, string a, string m1);
    }
}