using System.Globalization;
using System.Numerics;

namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// Security of cryptographic operations
    /// </summary>
    /// <remarks>
    /// <para>Warning: Do not change these values for existing encrypted data.</para>
    /// <para>Changing values will break compatibility with previously encrypted data.</para>
    /// </remarks>
    public static class SecurityConstants
    {
        // === AES-GCM Parameters ===

        /// <summary>Standard nonce size for AES-GCM (96 bits)</summary>
        public const int AesGcmNonceSize = 12;

        /// <summary>Standard authentication tag size for AES-GCM (128 bits).</summary>
        public const int AesGcmTagSize = 16;
        /// <summary>Minimum allowed tag size (96 bits).</summary>
        public const int AesGcmTagSizeMin = 12;
        /// <summary>Maximum allowed tag size (128 bits).</summary>
        public const int AesGcmTagSizeMax = 16;

        // === Key Parameters ===

        /// <summary>Default key size for AES-256 (256 bits).</summary>
        public const int KeySizeBytes = 32;

        // === KDF Parameters ===

        /// <summary>Default PBKDF2 iterations (balanced security/performance as of 2024).</summary>
        public const int Pbkdf2IterationsDefault = 600_000;
        
        /// <summary>Minimum safe PBKDF2 iterations. Values below this are rejected.</summary>
        public const int Pbkdf2IterationsMinimum = 100_000;
        
    }
}