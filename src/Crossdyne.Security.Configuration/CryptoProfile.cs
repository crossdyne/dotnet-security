namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// 
    /// </summary>
    public class CryptoProfile
    {
        /// <summary>
        /// 
        /// </summary>
        public CryptoVersion Version { get; init; }
        
        /// <summary>
        /// 
        /// </summary>
        public KdfOptions KdfOptions { get; init; } = null!;

        /// <summary>
        /// 
        /// </summary>
        public AesGcmOptions AesGcmOptions { get; init; } = null!;
    }
}