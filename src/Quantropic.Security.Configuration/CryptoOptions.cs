using System.Security.Cryptography;
using System.Text;
using Quantropic.Security.Exceptions;

namespace Quantropic.Security.Configuration
{
    /// <summary>
    /// Configuration options for cryptographic operations.
    /// </summary>
    public class CryptoOptions
    {
        // === AES-GCM Parameters ===

        private int _nonceSiz = SecurityConstants.AesGcmNonceSize;

        /// <summary>
        /// Gets or sets the nonce size for AES-GCM encryption.
        /// </summary>
        /// <remarks>
        /// AES-GCM standard requires a 12-byte (96-bit) nonce. 
        /// Setting a different value will throw <see cref="ArgumentOutOfRangeException"/>.
        /// </remarks>
        public int NonceSize
        {
            get => _nonceSiz;
            set
            {
                if (value != SecurityConstants.AesGcmNonceSize)
                    throw new ArgumentOutOfRangeException(nameof(value), $"AES-GCM requires {SecurityConstants.AesGcmNonceSize}-byte nonce for standard compliance.");

                _nonceSiz = value;
            }
        }

        private int _tagSize = SecurityConstants.AesGcmTagSize;

        /// <summary>
        /// Gets or sets the authentication tag size in bytes for AES-GCM.
        /// </summary>
        /// <remarks>
        /// Valid range is defined by <see cref="SecurityConstants.AesGcmTagSizeMin"/> 
        /// to <see cref="SecurityConstants.AesGcmTagSizeMax"/>. 
        /// Recommended value is 16 bytes for optimal security.
        /// </remarks>
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

        // === KDF Parameters ===

        private int _pbkdf2Iterations = SecurityConstants.Pbkdf2IterationsDefault;

        /// <summary>
        /// Gets or sets the number of iterations for PBKDF2 key derivation.
        /// </summary>
        /// <remarks>
        /// Higher values increase security but also computation time. 
        /// Minimum safe value is defined by <see cref="SecurityConstants.Pbkdf2IterationsMinimum"/>.
        /// </remarks>
        public int Pbkdf2Iterations
        {
            get => _pbkdf2Iterations;
            set
            {
                if (value < SecurityConstants.Pbkdf2IterationsMinimum)
                    throw new ArgumentOutOfRangeException(nameof(value), $"PBKDF2 iterations must be at least {SecurityConstants.Pbkdf2IterationsMinimum} for security.");

                _pbkdf2Iterations = value;
            }
        }

         // === Additional Features ===

        /// <summary>
        /// Gets or sets optional Additional Authenticated Data (AAD) for AES-GCM.
        /// </summary>
        /// <remarks>
        /// AAD is authenticated but not encrypted. It can be used to bind 
        /// contextual data to the ciphertext without encrypting it.
        /// </remarks>
        public byte[]? AssociatedData { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to compress data before encryption.
        /// </summary>
        /// <remarks>
        /// Compression can reduce ciphertext size but may introduce security risks 
        /// if applied to user-controlled input (CRIME/BREACH attacks). Use with caution.
        /// </remarks>
        public bool CompressBeforeEncrypt { get; set; } = false;

        // === Validation ===

        /// <summary>
        /// Validates the current configuration and throws <see cref="SecurityException"/> 
        /// if any parameter is outside safe bounds.
        /// </summary>
        /// <exception cref="SecurityException">
        /// Thrown when <see cref="Pbkdf2Iterations"/> or <see cref="TagSize"/> 
        /// are below minimum security thresholds.
        /// </exception>
        public void Validate()
        {
            if (Pbkdf2Iterations < SecurityConstants.Pbkdf2IterationsMinimum)
                throw new SecurityException($"Pbkdf2Iterations ({Pbkdf2Iterations}) is below minimum safe value.");
            
            if (TagSize < SecurityConstants.AesGcmTagSizeMin || TagSize > SecurityConstants.AesGcmTagSizeMax)
                throw new SecurityException($"Tag size must be between {SecurityConstants.AesGcmTagSizeMin} and {SecurityConstants.AesGcmTagSizeMax} bytes.");
        }

         // === Presets ===

         /// <summary>
         /// Gets the default cryptographic configuration preset.
         /// </summary>
         /// <remarks>
         /// Uses standard AES-GCM parameters and default PBKDF2 iterations 
         /// defined in <see cref="SecurityConstants"/>.
         /// </remarks>
         public static CryptoOptions Default => new();

         /// <summary>
         /// Gets a high-security preset with increased PBKDF2 iterations.
         /// </summary>
         /// <remarks>
         /// Recommended for protecting highly sensitive data. 
         /// Uses <see cref="SecurityConstants.Pbkdf2IterationsRecommended"/> 
         /// for stronger key derivation at the cost of performance.
         /// </remarks>
         public static CryptoOptions HightSecurity => new()
         {
            Pbkdf2Iterations = SecurityConstants.Pbkdf2IterationsRecommended  
         };

         /// <summary>
         /// Gets a legacy compatibility preset with reduced PBKDF2 iterations.
         /// </summary>
         /// <remarks>
         /// Use only for backward compatibility with older systems. 
         /// Not recommended for new deployments due to lower security margin.
         /// </remarks>
         public static CryptoOptions Legacy { get; } = new()
         {
            Pbkdf2Iterations = 100_000
         };

        // === Builder ===

        /// <summary>
        /// Creates a new instance of <see cref="CryptoOptionsBuilder"/> 
        /// for fluent configuration of cryptographic options.
        /// </summary>
        /// <returns>A new builder instance.</returns>
        public static CryptoOptionsBuilder Create() => new();

        /// <summary>
        /// Fluent builder for configuring <see cref="CryptoOptions"/>.
        /// </summary>
        public sealed class CryptoOptionsBuilder
        {
            private readonly CryptoOptions _options = new();

            /// <summary>
            /// Sets the nonce size for AES-GCM encryption.
            /// </summary>
            /// <param name="size">Nonce size in bytes (must be 12 for AES-GCM).</param>
            /// <returns>The current builder instance for chaining.</returns>
            /// <exception cref="ArgumentOutOfRangeException">
            /// Thrown if <paramref name="size"/> is not equal to 
            /// <see cref="SecurityConstants.AesGcmNonceSize"/>.
            /// </exception>
            public CryptoOptionsBuilder WithNonceSize(int size)
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
            public CryptoOptionsBuilder WithTagSize(int size)
            {
                _options.TagSize = size;
                return this;
            }

            /// <summary>
            /// Sets the number of PBKDF2 iterations for key derivation.
            /// </summary>
            /// <param name="iterations">Number of iterations (minimum: <see cref="SecurityConstants.Pbkdf2IterationsMinimum"/>).</param>
            /// <returns>The current builder instance for chaining.</returns>
            /// <exception cref="ArgumentOutOfRangeException">
            /// Thrown if <paramref name="iterations"/> is below the minimum safe value.
            /// </exception>
             public CryptoOptionsBuilder WithPbkdf2Iterations(int iterations)
            {
                _options.Pbkdf2Iterations = iterations;
                return this;
            }

            /// <summary>
            /// Configures PBKDF2 with recommended high-security iteration count.
            /// </summary>
            /// <returns>The current builder instance for chaining.</returns>
            /// <remarks>
            /// Sets iterations to <see cref="SecurityConstants.Pbkdf2IterationsRecommended"/> 
            /// for enhanced protection against brute-force attacks.
            /// </remarks>
            public CryptoOptionsBuilder WithHighSecurityKdf()
            {
                _options.Pbkdf2Iterations = SecurityConstants.Pbkdf2IterationsRecommended;
                return this;
            }

            /// <summary>
            /// Sets Additional Authenticated Data (AAD) as byte array.
            /// </summary>
            /// <param name="aad">The AAD bytes, or <c>null</c> to clear.</param>
            /// <returns>The current builder instance for chaining.</returns>
            public CryptoOptionsBuilder WithAssociatedData(byte[]? aad)
            {
                _options.AssociatedData = aad;
                return this;
            }

            /// <summary>
            /// Sets Additional Authenticated Data (AAD) from UTF-8 string.
            /// </summary>
            /// <param name="aadText">The AAD text to encode as UTF-8 bytes.</param>
            /// <returns>The current builder instance for chaining.</returns>
            public CryptoOptionsBuilder WithAssociatedData(string aadText)
            {
                _options.AssociatedData = Encoding.UTF8.GetBytes(aadText);
                return this;
            }

            /// <summary>
            /// Builds and validates the final <see cref="CryptoOptions"/> instance.
            /// </summary>
            /// <returns>A validated <see cref="CryptoOptions"/> object ready for use.</returns>
            /// <exception cref="SecurityException">
            /// Thrown if the configured options fail validation.
            /// </exception>
            public CryptoOptions Build()
            {
                _options.Validate();
                return _options;
            }
        }
    }
}