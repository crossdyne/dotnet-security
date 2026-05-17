using Crossdyne.Security.Exceptions;

namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// Registry of predefined <see cref="CryptoProfile"/> instances by version.
    /// Thread-safe, returns a fresh profile per call.
    /// </summary>
    public static class CryptoProfileRegistry
    {
        /// <summary>
        /// Returns a <see cref="CryptoProfile"/> for the specified <paramref name="version"/>.
        /// Supported versions: <see cref="CryptoVersion.V1"/> (default KDF + AES-GCM).
        /// </summary>
        /// <exception cref="SecurityException">Version not supported.</exception>
        public static CryptoProfile GetProfile(CryptoVersion version)
        {
            return version switch
            {
                CryptoVersion.V1 => new CryptoProfile
                {
                  Version = CryptoVersion.V1,
                  KdfOptions = KdfOptions.Default,
                  AesGcmOptions = AesGcmOptions.Default  
                },
                _ => throw new SecurityException($"Unsupported crypto version: {version}")
            };
        }

        /// <summary>
        /// Latest supported profile. Currently <see cref="CryptoVersion.V1"/>.
        /// Use explicit version for long-term stored data to avoid future changes.
        /// </summary>
        public static CryptoProfile Latest => GetProfile(CryptoVersion.V1);
    }
}