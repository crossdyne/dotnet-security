namespace Crossdyne.Security.Abstractions
{
    /// <summary>
    /// Server-side SRP-6a: challenge generation, client proof verification, server proof creation.
    /// </summary>
    public interface ISrpServer
    {
        /// <summary>
        /// Generates server challenge B and session state from verifier.
        /// </summary>
        /// <param name="ctx">SRP context.</param>
        /// <param name="login">User login.</param>
        /// <param name="verifierBytes">Stored verifier v as byte array.</param>
        /// <param name="salt">Auth salt.</param>
        /// <returns><see cref="SrpSessionState"/> containing private b, verifier, public B.</returns>
        SrpSessionState GetSrpChallenge(string login, byte[] verifierBytes, byte[] salt, SrpContext ctx);

        /// <summary>
        /// Verifies client M1 and returns server M2 proof.
        /// </summary>
        /// <param name="ctx">SRP context.</param>
        /// <param name="sessionState">Server session state.</param>
        /// <param name="a">Client public A (Base64).</param>
        /// <param name="m1">Client proof M1 (Base64).</param>
        /// <returns>Server proof M2 as Base64 string.</returns>
        string VerifySrpProof(SrpSessionState sessionState, string a, string m1, SrpContext ctx);
    }
}