using System.Text;
using Crossdyne.Security.Exceptions;

namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// Configuration options for AES-GCM encryption/decryption.
    /// Mutable, not thread-safe. Use <see cref="AesGcmOptionsBuilder"/> for immutable setups.
    /// </summary>
    public class AesGcmOptions
    {
        private int _nonceSize = SecurityConstants.AesGcmNonceSize;

        /// <summary>
        /// Nonce size in bytes. Must be 12 (NIST SP 800-38D). Default 12.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Value is not 12.</exception>
        public int NonceSize
        {
            get => _nonceSize;
            set
            {
                if (value != SecurityConstants.AesGcmNonceSize)
                    throw new ArgumentOutOfRangeException(nameof(value), $"AES-GCM requires {SecurityConstants.AesGcmNonceSize}-byte nonce for standard compliance.");

                _nonceSize = value;
            }
        }

        private int _tagSize = SecurityConstants.AesGcmTagSize;

        /// <summary>
        /// Tag size in bytes. Range 12–16, default 16 (recommended).
        /// Smaller values reduce overhead but increase forgery risk.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Outside 12–16.</exception>
        public int TagSize
        {
            get => _tagSize;
            set
            {
                if (value < SecurityConstants.AesGcmTagSizeMin || value > SecurityConstants.AesGcmTagSizeMax)
                    throw new ArgumentOutOfRangeException(nameof(value), $"Tag size must be between {SecurityConstants.AesGcmTagSizeMin} and {SecurityConstants.AesGcmTagSizeMax} bytes.");
                
                _tagSize = value;
            }
        }

        /// <summary>
        /// Optional Additional Authenticated Data (AAD). Stored by reference;
        /// if mutability is a concern, pass a copy.
        /// AAD is authenticated but not encrypted.
        /// </summary>
        public byte[]? AssociatedData { get; set; }


        /// <summary>
        /// Validates <see cref="TagSize"/> against the allowed range.
        /// </summary>
        /// <exception cref="SecurityException">Invalid tag size.</exception>
        public void Validate()
        {
            if (TagSize < SecurityConstants.AesGcmTagSizeMin || TagSize > SecurityConstants.AesGcmTagSizeMax)
                throw new SecurityException($"Tag size must be between {SecurityConstants.AesGcmTagSizeMin} and {SecurityConstants.AesGcmTagSizeMax} bytes.");
        }

        // === Presets ===

        /// <summary>Default preset: nonce=12, tag=16, no AAD.</summary>
        public static AesGcmOptions Default => new();

        // === Builder ===

        /// <summary>Creates a new builder for fluent configuration.</summary>
        public static AesGcmOptionsBuilder Create() => new();

        /// <summary>Fluent builder for <see cref="AesGcmOptions"/>.</summary>
        public sealed class AesGcmOptionsBuilder
        {
            private readonly AesGcmOptions _options = new();

            /// <summary>Sets nonce size. Must be 12.</summary>
            /// <exception cref="ArgumentOutOfRangeException">Not 12.</exception>
            public AesGcmOptionsBuilder WithNonceSize(int size)
            {
                _options.NonceSize = size;
                return this;
            }

            /// <summary>Sets tag size (12–16).</summary>
            /// <exception cref="ArgumentOutOfRangeException">Outside valid range.</exception>
            public AesGcmOptionsBuilder WithTagSize(int size)
            {
                _options.TagSize = size;
                return this;
            }

            /// <summary>Sets AAD from bytes. Stored by reference; consider a copy if needed.</summary>
            public AesGcmOptionsBuilder WithAssociatedData(byte[]? aad)
            {
                _options.AssociatedData = aad;
                return this;
            }

            /// <summary>
            /// Sets AAD from a UTF-8 string. Null/empty clears AAD.
            /// </summary>
            public AesGcmOptionsBuilder WithAssociatedData(string aadText)
            {
                _options.AssociatedData = string.IsNullOrEmpty(aadText) ? null : Encoding.UTF8.GetBytes(aadText);
                return this;
            }

            /// <summary>Builds and validates the options.</summary>
            /// <exception cref="SecurityException">Validation failed.</exception>
            public AesGcmOptions Build()
            {
                _options.Validate();
                return _options;
            }
        }
    }
}