using System.Security.Cryptography;
using Crossdyne.Security.Exceptions;

namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// Immutable PBKDF2/HKDF configuration. All parameters are validated at the moment of initialization.
    /// </summary>
    /// <remarks>
    /// Do not construct manually unless you explicitly call <see cref="Validate"/> before use.
    /// Prefer using versioned presets such as <see cref="V1"/>.
    /// </remarks>
    public sealed record KdfOptions
    {
        private int _pbkdf2Iterations;

        /// <summary>
        /// PBKDF2 iteration count. Must be at least <see cref="SecurityConstants.Pbkdf2IterationsMinimum"/>.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Below the absolute minimum.</exception>
        public required int Pbkdf2Iterations
        {
            get => _pbkdf2Iterations;
            init
            {
                if (value < SecurityConstants.Pbkdf2IterationsMinimum)
                    throw new ArgumentOutOfRangeException(nameof(value),
                        $"PBKDF2 iterations must be at least {SecurityConstants.Pbkdf2IterationsMinimum}.");

                _pbkdf2Iterations = value;
            }
        }
        
        private HashAlgorithmName _hashAlgorithm = HashAlgorithmName.SHA256;

        /// <summary>
        /// Hash algorithm used by PBKDF2 and HKDF. Supported: SHA256, SHA384, SHA512.
        /// </summary>
        /// <exception cref="ArgumentOutOfRangeException">Unsupported algorithm name.</exception>
        public required HashAlgorithmName HashAlgorithm
        {
            get => _hashAlgorithm;
            init
            {
                if (value != HashAlgorithmName.SHA256 &&
                    value != HashAlgorithmName.SHA384 &&
                    value != HashAlgorithmName.SHA512)
                {
                    throw new ArgumentOutOfRangeException(nameof(value),
                        $"Unsupported hash algorithm: {value.Name}. Supported: SHA256, SHA384, SHA512.");
                }

                _hashAlgorithm = value;
            }
        }

        /// <summary>
        /// Final validation guard. Idempotent if object was constructed via init.
        /// </summary>
        /// <exception cref="SecurityException">Any parameter violates security floor.</exception>
        public void Validate()
        {
            if (Pbkdf2Iterations < SecurityConstants.Pbkdf2IterationsMinimum)
                throw new SecurityException($"PBKDF2 iterations ({Pbkdf2Iterations}) are below the safe minimum.");

            if (HashAlgorithm != HashAlgorithmName.SHA256 &&
                HashAlgorithm != HashAlgorithmName.SHA384 &&
                HashAlgorithm != HashAlgorithmName.SHA512)
            {
                throw new SecurityException($"Hash algorithm {HashAlgorithm.Name} is not supported.");
            }
        }

        // === Versioned Presets ===

        /// <summary>
        /// V1 preset: SHA-256, 600 000 iterations.
        /// These exact values are frozen for all V1-derived keys.
        /// </summary>
        public static readonly KdfOptions V1 = new()
        {
            Pbkdf2Iterations = 600_000,
            HashAlgorithm = HashAlgorithmName.SHA256
        };
    }
}