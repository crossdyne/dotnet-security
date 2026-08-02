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
        /// <param name="login">User login.</param>
        /// <param name="verifierBytes">Stored verifier v as byte array.</param>
        /// <param name="salt">Authentication salt.</param>
        /// <param name="ctx">SRP context.</param>
        /// <returns><see cref="SrpSessionState"/> containing private b, verifier, and public B.</returns>
        /// <exception cref="ArgumentNullException"><paramref name="verifierBytes"/> is null.</exception>
        /// <exception cref="ArgumentException"><paramref name="login"/> is null or empty.</exception>
        /// <exception cref="Exceptions.SrpVerificationException">Verifier is corrupted or invalid B generated.</exception>
        SrpSessionState GetSrpChallenge(string login, byte[] verifierBytes, byte[] salt, SrpContext ctx);

        /// <summary>
        /// Verifies client M1 and returns server M2 proof.
        /// </summary>
        /// <param name="sessionState">Server session state.</param>
        /// <param name="a">Client public A (Base64).</param>
        /// <param name="m1">Client proof M1 (Base64).</param>
        /// <param name="ctx">SRP context.</param>
        /// <returns>Server proof M2 as Base64 string.</returns>
        /// <exception cref="Exceptions.SrpVerificationException">Client proof invalid or parameters out of range.</exception>
        /// <exception cref="Exceptions.SecurityException">Shared secret S is zero (possible malicious A).</exception>
        string VerifySrpProof(SrpSessionState sessionState, string a, string m1, SrpContext ctx);
    }
}