namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// Immutable cryptographic profile bundling version, KDF, and AES-GCM settings.
    /// Thread-safe after construction.
    /// </summary>
    /// <remarks>
    /// All properties are <c>init</c>-only; use object initializer syntax to construct.
    /// </remarks>
    public class CryptoProfile
    {
        /// <summary>Protocol version, influencing KDF defaults, cipher modes, and serialization.</summary>
        public CryptoVersion Version { get; init; }
        
        /// <summary>
        /// Key derivation parameters. Must be set at construction.
        /// </summary>
        /// <remarks>
        /// Do not reuse the same salt across derivations.
        /// </remarks>
        public KdfOptions KdfOptions { get; init; } = null!;

        /// <summary>
        /// AES-GCM encryption parameters. Must be set at construction.
        /// </summary>
        /// <remarks>
        /// Nonce must be unique per key; reuse breaks security.
        /// </remarks>
        public AesGcmOptions AesGcmOptions { get; init; } = null!;
    }
}