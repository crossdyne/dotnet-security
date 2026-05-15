using Crossdyne.Security.Exceptions;

namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// 
    /// </summary>
    public static class CryptoProfileRegistry
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="version"></param>
        /// <returns></returns>
        /// <exception cref="SecurityException"></exception>
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
        /// 
        /// </summary>
        public static CryptoProfile Latest => GetProfile(CryptoVersion.V1);
    }
}