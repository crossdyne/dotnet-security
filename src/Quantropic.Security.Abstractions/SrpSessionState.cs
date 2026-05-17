namespace Quantropic.Security.Abstractions
{
    /// <summary>
    /// Represents the server-side state during the Secure Remote Password (SRP) protocol flow.
    /// Stores the user's login, the server's ephemeral private key (b),
    /// the user's verifier from the database, and the server's ephemeral public key (B)
    /// to be sent to the client for session key generation.
    /// </summary>
    /// <param name="Login">The user's login identifier (username/email)</param>
    /// <param name="PrivateKeyB">The server's ephemeral private key (b) - keep secure, never sent to client</param>
    /// <param name="Verifier">The user's verifier (v) retrieved from the database</param>
    /// <param name="PublicKeyB">The server's ephemeral public key (B) sent to the client</param>
    public record SrpSessionState(string Login, string PrivateKeyB, string Verifier, string PublicKeyB);
}