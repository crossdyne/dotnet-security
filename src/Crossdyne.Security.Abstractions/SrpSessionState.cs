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
        /// Логин пользователя
        /// </summary>
        public string Login { get; }
        
        /// <summary>Серверный эфемерный секрет b. Требует явного стирания.</summary>
        public byte[] PrivateKeyB { get; }
        
        /// <summary>SRP-верификатор v (публичный, но бинарный).</summary>
        public ReadOnlyMemory<byte> Verifier { get; }
        
        /// <summary>Публичный эфемерный ключ B.</summary>
        public ReadOnlyMemory<byte> PublicKeyB { get; }

        /// <param name="login">The user's login identifier (username/email)</param>
        /// <param name="privateKeyB">The server's ephemeral private key (b) - keep secure, never sent to client</param>
        /// <param name="verifier">The user's verifier (v) retrieved from the database</param>
        /// <param name="publicKeyB">The server's ephemeral public key (B) sent to the client</param>
        public SrpSessionState(string login, byte[] privateKeyB, ReadOnlyMemory<byte> verifier, ReadOnlyMemory<byte> publicKeyB)
        {
            Login = login;
            PrivateKeyB = privateKeyB;
            Verifier = verifier;
            PublicKeyB = publicKeyB;
        }

        /// <summary>
        /// Очистка
        /// </summary>
        public void Dispose()
        {
            CryptographicOperations.ZeroMemory(PrivateKeyB);
        }
    }

}