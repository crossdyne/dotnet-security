using Crossdyne.Security.Exceptions;

namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// Immutable AES-GCM configuration. All parameters are validated at the moment of initialization.
    /// </summary>
    /// <remarks>
    /// Do not construct manually unless you explicitly call <see cref="Validate"/> before use.
    /// Prefer using versioned presets such as <see cref="V1"/>.
    /// </remarks>
    public sealed record AesGcmOptions
    {
        private int _nonceSize;

        /// <summary>
        /// Nonce size in bytes. Must equal <see cref="SecurityConstants.AesGcmNonceSize"/> (12).
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Value is not 12.</exception>
        public required int NonceSize
        {
            get => _nonceSize;
            init
            {
                if (value != SecurityConstants.AesGcmNonceSize)
                    throw new ArgumentOutOfRangeException(nameof(value),
                        $"AES-GCM requires exactly {SecurityConstants.AesGcmNonceSize}-byte nonce per NIST SP 800-38D.");

                _nonceSize = value;
            }
        }
        
        private int _tagSize;

        /// <summary>
        /// Authentication tag size in bytes. Allowed range: 12–16.
        /// Smaller values reduce overhead but increase forgery probability.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Outside the allowed 12–16 byte range.</exception>
        public required int TagSize
        {
            get => _tagSize;
            init
            {
                if (value < SecurityConstants.AesGcmTagSizeMin || value > SecurityConstants.AesGcmTagSizeMax)
                    throw new ArgumentOutOfRangeException(nameof(value),
                        $"Tag size must be between {SecurityConstants.AesGcmTagSizeMin} and {SecurityConstants.AesGcmTagSizeMax} bytes.");

                _tagSize = value;
            }
        }

        /// <summary>
        /// Final validation guard. Safe to call multiple times; idempotent if object was constructed via init.
        /// </summary>
        /// <exception cref="SecurityException">Any parameter violates algorithmic constraints.</exception>
        public void Validate()
        {
            // Guard against reflection / deserialization bypassing init validation.
            if (NonceSize != SecurityConstants.AesGcmNonceSize)
                throw new SecurityException($"Nonce size {NonceSize} is invalid for AES-GCM.");

            if (TagSize < SecurityConstants.AesGcmTagSizeMin || TagSize > SecurityConstants.AesGcmTagSizeMax)
                throw new SecurityException($"Tag size {TagSize} is outside the allowed range.");
        }

        // === Versioned Presets ===

        /// <summary>
        /// V1 preset: nonce=12, tag=16, no AAD.
        /// These exact values are frozen for all V1-encrypted payloads.
        /// </summary>
        public static readonly AesGcmOptions V1 = new()
        {
            NonceSize = SecurityConstants.AesGcmNonceSize,
            TagSize = SecurityConstants.AesGcmTagSizeMax,
        };
    }
}