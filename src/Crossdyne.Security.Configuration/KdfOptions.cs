using System.Security.Cryptography;
using Crossdyne.Security.Exceptions;

namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// Configuration options for Key Derivation Functions (KDF).
    /// </summary>
    /// <remarks>
    /// This class encapsulates parameters for password-based key derivation, 
    /// currently focused on PBKDF2. All values are validated against security 
    /// best practices defined in <see cref="SecurityConstants"/>.
    /// </remarks>
    public class KdfOptions
    {
        private int _pbkdf2Iterations = SecurityConstants.Pbkdf2IterationsDefault;

        /// <summary>
        /// Gets or sets the number of iterations for PBKDF2 key derivation.
        /// </summary>
        /// <value>
        /// The iteration count. Default is <see cref="SecurityConstants.Pbkdf2IterationsDefault"/>.
        /// </value>
        /// <remarks>
        /// Higher iteration counts increase resistance to brute-force and dictionary attacks 
        /// but also increase computation time. Minimum safe value is defined by 
        /// <see cref="SecurityConstants.Pbkdf2IterationsMinimum"/>.
        /// </remarks>
        /// <exception cref="ArgumentOutOfRangeException">
        /// Thrown when the value is below <see cref="SecurityConstants.Pbkdf2IterationsMinimum"/>.
        /// </exception>
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

        private HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;

        /// <summary>
        /// 
        /// </summary>
        public HashAlgorithmName HashAlgorithm
        {
            get => _hashAlgorithm;
            set
            {
                if (value != HashAlgorithmName.SHA256 &&
                    value != HashAlgorithmName.SHA384 &&
                    value != HashAlgorithmName.SHA512)
                {
                    throw new ArgumentOutOfRangeException(nameof(value), $"Unsupported hash algorithm: {value.Name}");
                }
                
                _hashAlgorithm = value;
            }
        }

        /// <summary>
        /// Validates the current configuration.
        /// </summary>
        /// <remarks>
        /// Ensures that <see cref="Pbkdf2Iterations"/> meets the minimum security threshold 
        /// defined by <see cref="SecurityConstants.Pbkdf2IterationsMinimum"/>.
        /// </remarks>
        /// <exception cref="SecurityException">
        /// Thrown when <see cref="Pbkdf2Iterations"/> is below the minimum safe value.
        /// </exception>
        public void Validate()
        {
            if (Pbkdf2Iterations < SecurityConstants.Pbkdf2IterationsMinimum)
                throw new SecurityException($"Pbkdf2Iterations ({Pbkdf2Iterations}) is below minimum safe value.");
        }

        // === Presets ===

        /// <summary>
        /// Gets the default KDF configuration preset.
        /// </summary>
        /// <value>
        /// A new instance of <see cref="KdfOptions"/> with default PBKDF2 iterations 
        /// defined in <see cref="SecurityConstants"/>.
        /// </value>
        /// <remarks>
        /// Suitable for general-purpose key derivation where performance and security 
        /// need to be balanced.
        /// </remarks>
        public static KdfOptions Default => new();

        // === Builder ===

        /// <summary>
        /// Creates a new instance of <see cref="KdfOptionsBuilder"/> 
        /// for fluent configuration of KDF options.
        /// </summary>
        /// <returns>A new builder instance.</returns>
        public static KdfOptionsBuilder Create() => new();

        /// <summary>
        /// Fluent builder for configuring <see cref="KdfOptions"/>.
        /// </summary>
        /// <remarks>
        /// Provides a chainable API for setting PBKDF2 parameters with 
        /// immediate validation upon <see cref="Build"/>.
        /// </remarks>
        public sealed class KdfOptionsBuilder
        {
            private readonly KdfOptions _options = new();

            /// <summary>
            /// Sets the number of PBKDF2 iterations for key derivation.
            /// </summary>
            /// <param name="iterations">Number of iterations (minimum: <see cref="SecurityConstants.Pbkdf2IterationsMinimum"/>).</param>
            /// <returns>The current builder instance for chaining.</returns>
            /// <exception cref="ArgumentOutOfRangeException">
            /// Thrown if <paramref name="iterations"/> is below the minimum safe value.
            /// </exception>
            public KdfOptionsBuilder WithPbkdf2Iterations(int iterations)
            {
                _options.Pbkdf2Iterations = iterations;
                return this;
            }

            /// <summary>
            /// Builds and validates the final <see cref="KdfOptions"/> instance.
            /// </summary>
            /// <returns>A validated <see cref="KdfOptions"/> object ready for use.</returns>
            /// <exception cref="SecurityException">
            /// Thrown if the configured options fail validation.
            /// </exception>
            public KdfOptions Build()
            {
                _options.Validate();
                return _options;
            }
        }
    }
}