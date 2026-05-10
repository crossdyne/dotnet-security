using System.Text;
using Crossdyne.Security.Exceptions;

namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// Configuration options for AES-GCM encryption and decryption.
    /// </summary>
    /// <remarks>
    /// This class encapsulates parameters specific to AES-GCM authenticated encryption,
    /// including nonce size, authentication tag size, and optional Additional Authenticated Data (AAD).
    /// All values are validated against cryptographic standards defined in <see cref="SecurityConstants"/>.
    /// </remarks>
    public class AesGcmOptions
    {
        private int _nonceSize = SecurityConstants.AesGcmNonceSize;

        /// <summary>
        /// Gets or sets the nonce size for AES-GCM encryption.
        /// </summary>
        /// <value>
        /// The nonce size in bytes. Default is <see cref="SecurityConstants.AesGcmNonceSize"/> (12 bytes).
        /// </value>
        /// <remarks>
        /// AES-GCM standard (NIST SP 800-38D) requires a 12-byte (96-bit) nonce for optimal security 
        /// and performance. Setting a different value will throw <see cref="ArgumentOutOfRangeException"/>.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">
        /// Thrown when the value is not equal to <see cref="SecurityConstants.AesGcmNonceSize"/>.
        /// </exception>
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
        /// Gets or sets the authentication tag size in bytes for AES-GCM.
        /// </summary>
        /// <value>
        /// The tag size in bytes. Default is <see cref="SecurityConstants.AesGcmTagSize"/> (16 bytes).
        /// </value>
        /// <remarks>
        /// Valid range is defined by <see cref="SecurityConstants.AesGcmTagSizeMin"/> 
        /// to <see cref="SecurityConstants.AesGcmTagSizeMax"/>. 
        /// Recommended value is 16 bytes for optimal security and interoperability.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">
        /// Thrown when the value is outside the valid range.
        /// </exception>
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
        /// Gets or sets optional Additional Authenticated Data (AAD) for AES-GCM.
        /// </summary>
        /// <value>
        /// A byte array containing AAD, or <c>null</c> if no additional data is required.
        /// </value>
        /// <remarks>
        /// AAD is authenticated but not encrypted. It can be used to bind 
        /// contextual metadata (e.g., headers, protocol version) to the ciphertext 
        /// without including it in the encrypted payload.
        /// </remarks>
        public byte[]? AssociatedData { get; set; }


        /// <summary>
        /// Validates the current configuration.
        /// </summary>
        /// <remarks>
        /// Ensures that <see cref="TagSize"/> is within the safe bounds defined by 
        /// <see cref="SecurityConstants"/>. <see cref="NonceSize"/> is validated 
        /// by its setter and does not require additional checks here.
        /// </remarks>
        /// <exception cref="SecurityException">
        /// Thrown when <see cref="TagSize"/> is outside the valid range.
        /// </exception>
        public void Validate()
        {
            if (TagSize < SecurityConstants.AesGcmTagSizeMin || TagSize > SecurityConstants.AesGcmTagSizeMax)
                throw new SecurityException($"Tag size must be between {SecurityConstants.AesGcmTagSizeMin} and {SecurityConstants.AesGcmTagSizeMax} bytes.");
        }

        // === Presets ===

        /// <summary>
        /// Gets the default AES-GCM configuration preset.
        /// </summary>
        /// <value>
        /// A new instance of <see cref="AesGcmOptions"/> with standard parameters 
        /// defined in <see cref="SecurityConstants"/>.
        /// </value>
        /// <remarks>
        /// Uses 12-byte nonce, 16-byte authentication tag, and no AAD or compression.
        /// Suitable for most general-purpose encryption scenarios.
        /// </remarks>
        public static AesGcmOptions Default => new();

        // === Builder ===

        /// <summary>
        /// Creates a new instance of <see cref="AesGcmOptionsBuilder"/> 
        /// for fluent configuration of AES-GCM options.
        /// </summary>
        /// <returns>A new builder instance.</returns>
        public static AesGcmOptionsBuilder Create() => new();

        /// <summary>
        /// Fluent builder for configuring <see cref="AesGcmOptions"/>.
        /// </summary>
        /// <remarks>
        /// Provides a chainable API for setting AES-GCM parameters with 
        /// immediate validation upon <see cref="Build"/>.
        /// </remarks>
        public sealed class AesGcmOptionsBuilder
        {
            private readonly AesGcmOptions _options = new();

            /// <summary>
            /// Sets the nonce size for AES-GCM encryption.
            /// </summary>
            /// <param name="size">Nonce size in bytes (must be 12 for AES-GCM).</param>
            /// <returns>The current builder instance for chaining.</returns>
            /// <exception cref="ArgumentOutOfRangeException">
            /// Thrown if <paramref name="size"/> is not equal to 
            /// <see cref="SecurityConstants.AesGcmNonceSize"/>.
            /// </exception>
            public AesGcmOptionsBuilder WithNonceSize(int size)
            {
                _options.NonceSize = size;
                return this;
            }

            /// <summary>
            /// Sets the authentication tag size for AES-GCM.
            /// </summary>
            /// <param name="size">Tag size in bytes (between 12 and 16).</param>
            /// <returns>The current builder instance for chaining.</returns>
            /// <exception cref="ArgumentOutOfRangeException">
            /// Thrown if <paramref name="size"/> is outside the valid range 
            /// defined by <see cref="SecurityConstants.AesGcmTagSizeMin"/> 
            /// and <see cref="SecurityConstants.AesGcmTagSizeMax"/>.
            /// </exception>
            public AesGcmOptionsBuilder WithTagSize(int size)
            {
                _options.TagSize = size;
                return this;
            }

            /// <summary>
            /// Sets Additional Authenticated Data (AAD) as byte array.
            /// </summary>
            /// <param name="aad">The AAD bytes, or <c>null</c> to clear.</param>
            /// <returns>The current builder instance for chaining.</returns>
            public AesGcmOptionsBuilder WithAssociatedData(byte[]? aad)
            {
                _options.AssociatedData = aad;
                return this;
            }

            /// <summary>
            /// Sets Additional Authenticated Data (AAD) from UTF-8 string.
            /// </summary>
            /// <param name="aadText">The AAD text to encode as UTF-8 bytes.</param>
            /// <returns>The current builder instance for chaining.</returns>
            /// <remarks>
            /// If <paramref name="aadText"/> is null or empty, AAD is set to <c>null</c>.
            /// </remarks>
            public AesGcmOptionsBuilder WithAssociatedData(string aadText)
            {
                _options.AssociatedData = string.IsNullOrEmpty(aadText) ? null : Encoding.UTF8.GetBytes(aadText);
                return this;
            }

            /// <summary>
            /// Builds and validates the final <see cref="AesGcmOptions"/> instance.
            /// </summary>
            /// <returns>A validated <see cref="AesGcmOptions"/> object ready for use.</returns>
            /// <exception cref="SecurityException">
            /// Thrown if the configured options fail validation.
            /// </exception>
            public AesGcmOptions Build()
            {
                _options.Validate();
                return _options;
            }
        }
    }
}