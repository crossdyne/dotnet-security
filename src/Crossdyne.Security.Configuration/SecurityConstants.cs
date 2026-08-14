namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// Algorithmic constraints that are physically immutable (NIST specs, AES key sizes, etc.).
    /// These do not change between crypto versions.
    /// </summary>
    public static class SecurityConstants
    {
        // === AES-GCM Physical Constraints (NIST SP 800-38D) ===

        /// <summary>Standard nonce size for AES-GCM (96 bits). Fixed by the Galois/Counter mode specification.</summary>
        public const int AesGcmNonceSize = 12;

        /// <summary>Minimum allowed authentication tag size (96 bits).</summary>
        public const int AesGcmTagSizeMin = 12;

        /// <summary>Maximum allowed authentication tag size (128 bits).</summary>
        public const int AesGcmTagSizeMax = 16;

        // === AES Key Physical Constraints ===

        /// <summary>Key size for AES-256 (256 bits).</summary>
        public const int KeySizeBytes = 32;

        // === KDF Absolute Security Floor ===

        /// <summary>
        /// Absolute minimum PBKDF2 iterations for any profile version.
        /// Values below this are rejected regardless of version.
        /// </summary>
        public const int Pbkdf2IterationsMinimum = 100_000;
    }
}