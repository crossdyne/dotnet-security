using System.Security.Cryptography;
using Crossdyne.Security.Exceptions;

namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// Configuration options for PBKDF2 key derivation.
    /// Mutable, not thread-safe. Use <see cref="KdfOptionsBuilder"/> for fluent setup.
    /// </summary>
    public class KdfOptions
    {
        private int _pbkdf2Iterations = SecurityConstants.Pbkdf2IterationsDefault;

        /// <summary>
        /// PBKDF2 iteration count. Default <see cref="SecurityConstants.Pbkdf2IterationsDefault"/>.
        /// Higher values increase security but slow down derivation.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Below <see cref="SecurityConstants.Pbkdf2IterationsMinimum"/>.</exception>
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
        /// Hash algorithm used by PBKDF2. Supported: SHA256 (default), SHA384, SHA512.
        /// Changing the algorithm produces different derived keys.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Unsupported algorithm.</exception>
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
        /// Validates that <see cref="Pbkdf2Iterations"/> meets the minimum threshold.
        /// </summary>
        /// <exception cref="SecurityException">Iterations too low.</exception>
        public void Validate()
        {
            if (Pbkdf2Iterations < SecurityConstants.Pbkdf2IterationsMinimum)
                throw new SecurityException($"Pbkdf2Iterations ({Pbkdf2Iterations}) is below minimum safe value.");
        }

        // === Presets ===

        /// <summary>Default preset: SHA-256, <see cref="SecurityConstants.Pbkdf2IterationsDefault"/> iterations.</summary>
        public static KdfOptions Default => new();

        // === Builder ===

        /// <summary>Creates a builder for fluent configuration.</summary>
        public static KdfOptionsBuilder Create() => new();

        /// <summary>Fluent builder for <see cref="KdfOptions"/>.</summary>
        public sealed class KdfOptionsBuilder
        {
            private readonly KdfOptions _options = new();

            /// <summary>Sets PBKDF2 iterations. Minimum 100_000.</summary>
            /// <exception cref="ArgumentOutOfRangeException">Below minimum.</exception>
            public KdfOptionsBuilder WithPbkdf2Iterations(int iterations)
            {
                _options.Pbkdf2Iterations = iterations;
                return this;
            }

            /// <summary>Sets the hash algorithm (SHA256, SHA384, SHA512). Default SHA256.</summary>
            /// <exception cref="ArgumentOutOfRangeException">Unsupported algorithm.</exception>
            public KdfOptionsBuilder WithHashAlgorithm(HashAlgorithmName algorithm)
            {
                _options.HashAlgorithm = algorithm;
                return this;
            }

            /// <summary>Builds and validates the options.</summary>
            /// <exception cref="SecurityException">Validation failed.</exception>
            public KdfOptions Build()
            {
                _options.Validate();
                return _options;
            }
        }
    }
}