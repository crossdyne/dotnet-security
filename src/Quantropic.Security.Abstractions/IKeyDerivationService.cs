using Quantropic.Security.Configuration;

namespace Quantropic.Security.Abstractions
{
    /// <summary>
    /// Provides key derivation services using PBKDF2 algorithm.
    /// </summary>
    public interface IKeyDerivationService
    {
        /// <summary>
        /// Derives encryption key and authentication hash from a password using default PBKDF2 iterations.
        /// </summary>
        /// <param name="login">User Login.</param>
        /// <param name="password">The password to derive keys from.</param>
        /// <param name="salt">The salt value for key derivation.</param>
        /// <returns>A tuple containing the Key Encryption Key (KEK) and authentication hash.</returns>
        (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string login, string password, byte[] salt);

        /// <summary>
        /// Derives encryption key and authentication hash from a password with specified PBKDF2 iterations.
        /// </summary>
        /// <param name="login">User Login.</param>
        /// <param name="password">The password to derive keys from.</param>
        /// <param name="salt">The salt value for key derivation.</param>
        /// <param name="pbkdf2Iterations">The number of PBKDF2 iterations. If null, uses default value.</param>
        /// <returns>A tuple containing the Key Encryption Key (KEK) and authentication hash.</returns>
        (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string login, string password, byte[] salt, int? pbkdf2Iterations = null);

        /// <summary>
        /// Derives encryption key and authentication hash from a password with custom crypto options.
        /// </summary>
        /// <param name="login">User Login.</param>
        /// <param name="password">The password to derive keys from.</param>
        /// <param name="salt">The salt value for key derivation.</param>
        /// <param name="options">Optional crypto configuration options.</param>
        /// <returns>A tuple containing the Key Encryption Key (KEK) and authentication hash.</returns>
        public (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string login, string password, byte[] salt, CryptoOptions? options = null);
    }
}