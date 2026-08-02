using System.Security.Cryptography;
using Crossdyne.Security.Configuration;
using Crossdyne.Security.Exceptions;

namespace Crossdyne.Security.Abstractions
{
    /// <summary>
    /// Two-stage key derivation: PBKDF2 (master key) → HKDF (sub-keys). Thread-safe.
    /// </summary>
    /// <remarks>
    /// Derived sub-keys: KEK (AES-GCM) and AuthHash (server verification).
    /// HKDF info strings ensure key separation.
    /// Salts must be random, unique, and at least 16 bytes.
    /// Sensitive buffers are cleared after use.
    /// </remarks>
    public interface IKeyDerivationService
    {
        /// <summary>
        /// Full KDF configuration overload.
        /// Derivation: PBKDF2(identity:password) → HKDF(KEK, AuthHash).
        /// Identity is hashed as-is. Caller must normalize (trim, lowercase, etc.) 
        /// before calling to ensure cross-platform consistency.
        /// </summary>
        /// <param name="identity">User identity. Must be normalized by caller.</param>
        /// <param name="password">User password.</param>
        /// <param name="salt">Random unique salt (at least 16 bytes).</param>
        /// <param name="version">Crypto version; V1 uses default.</param>
        /// <returns>
        /// <c>Kek</c>: AES-256 key for data encryption.
        /// <c>AuthHash</c>: Base64-encoded server verification hash.
        /// </returns>
        /// <exception cref="ArgumentException">Identity or password is null or empty.</exception>
        /// <exception cref="InvalidKeyException">Salt is null or shorter than 16 bytes.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Invalid options.</exception>
        /// <exception cref="SecurityException">Derivation error.</exception>
        (byte[] Kek, string AuthHash) DeriveKeysFromPassword(
            string identity,
            string password,
            byte[] salt,
            CryptoVersion version);

        /// <summary>
        /// Derives an SRP-compatible authentication hash (output size = hash output length).
        /// Identity is hashed as-is. Caller must normalize (trim, lowercase, etc.) 
        /// before calling to ensure cross-platform consistency.
        /// </summary>
        /// <param name="identity">User identity. Must be normalized by caller.</param>
        /// <param name="password">User password.</param>
        /// <param name="salt">Random unique salt (at least 16 bytes).</param>
        /// <param name="srpHashAlgorithm">Hash algorithm for SRP verifier.</param>
        /// <param name="version">Crypto version; V1 uses default.</param>
        /// <returns>Raw hash bytes for use as SRP verifier input (x).</returns>
        /// <exception cref="ArgumentException">
        /// Identity or password is null or empty, or hash algorithm is unsupported.
        /// </exception>
        /// <exception cref="InvalidKeyException">Salt is null or shorter than 16 bytes.</exception>
        /// <exception cref="SecurityException">Derivation error.</exception>
        byte[] DeriveAuthHashForSrp(
            string identity,
            string password,
            byte[] salt,
            HashAlgorithmName srpHashAlgorithm,
            CryptoVersion version);
    }
}