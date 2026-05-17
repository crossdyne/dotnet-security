namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// Supported cryptographic profile versions.
    /// </summary>
    /// <remarks>
    /// <see cref="V1"/>: baseline (PBKDF2-HMAC-SHA256, AES-256-GCM, 12-byte nonce, 16-byte tag).
    /// Append new members sequentially; never change existing values.
    /// </remarks>
    public enum CryptoVersion
    {
        /// <summary>Version 1 — initial profile.</summary>
        V1 = 1,
    }
}