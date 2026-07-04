using System.Security.Cryptography;

namespace Crossdyne.Security.Abstractions
{
    /// <summary>
    /// Represents the server-side state during the Secure Remote Password (SRP) protocol flow.
    /// Stores the user's login, the server's ephemeral private key (b),
    /// the user's verifier from the database, and the server's ephemeral public key (B)
    /// to be sent to the client for session key generation.
    /// </summary>
    public sealed class SrpSessionState : IDisposable
    {
        /// <summary>
        /// User login
        /// </summary>
        public string Login { get; }
        
        /// <summary>Server ephemeral secret b. Requires explicit erasure.</summary>
        public byte[] PrivateKeyB { get; }
        
        /// <summary>SRP verifier v (public, but binary).</summary>
        public ReadOnlyMemory<byte> Verifier { get; }
        
        /// <summary>Public ephemeral key B</summary>
        public ReadOnlyMemory<byte> PublicKeyB { get; }

        /// <summary>User salt s (needed for RFC 5054 M1).</summary>
        public ReadOnlyMemory<byte> Salt { get; }

        /// <param name="login">The user's login identifier (username/email)</param>
        /// <param name="privateKeyB">The server's ephemeral private key (b) - keep secure, never sent to client</param>
        /// <param name="verifier">The user's verifier (v) retrieved from the database</param>
        /// <param name="publicKeyB">The server's ephemeral public key (B) sent to the client</param>
        public SrpSessionState(string login, byte[] privateKeyB, ReadOnlyMemory<byte> verifier, ReadOnlyMemory<byte> publicKeyB, ReadOnlyMemory<byte> salt)
        {
            Login = login;
            PrivateKeyB = privateKeyB;
            Verifier = verifier;
            PublicKeyB = publicKeyB;
            Salt = salt;
        }

        /// <summary>
        /// Resource cleaning
        /// </summary>
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(PrivateKeyB);
        }
    }

}