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
        /// <param name="identity"></param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="options">KDF options; null uses default.</param>
        /// <exception cref="ArgumentException">Password null/empty.</exception>
        /// <exception cref="InvalidKeyException">Salt null.</exception>
        /// <exception cref="ArgumentOutOfRangeException">Invalid options.</exception>
        /// <exception cref="SecurityException">Derivation error.</exception>
        public (byte[] Kek, string AuthHash) DeriveKeysFromPassword(string identity, string password, byte[] salt, KdfOptions? options = null);
        
        /// <summary>
        /// Derives an SRP-compatible authentication hash (output size = hash output length).
        /// Identity is hashed as-is. Caller must normalize (trim, lowercase, etc.) 
        /// before calling to ensure cross-platform consistency.
        /// <param name="identity"></param>
        /// <param name="password"></param>
        /// <param name="salt"></param>
        /// <param name="srpHashAlgorithm"></param>
        /// <param name="options"></param>
        /// <returns>Raw hash bytes for use as SRP verifier input (x).</returns>
        /// <exception cref="ArgumentException">Password null/empty, or unsupported hash.</exception>
        /// <exception cref="InvalidKeyException">Salt null.</exception>
        /// <exception cref="SecurityException">Derivation error.</exception>
        /// </summary>
        byte[] DeriveAuthHashForSrp(string identity, string password, byte[] salt, HashAlgorithmName srpHashAlgorithm,  KdfOptions? options = null);
    }
}