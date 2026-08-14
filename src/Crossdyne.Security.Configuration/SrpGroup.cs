namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// SRP-6a Diffie-Hellman groups (RFC 5054).
    /// </summary>
    /// <remarks>
    /// 1024 (~80) deprecated, 1536 (~90) legacy, 2048 (~112) baseline,
    /// 3072+ (≥128) preferred. g=2 for ≤2048, g=5 for 3072-6144, g=19 for 8192.
    /// Always use <see cref="SrpGroupParams"/> to get N and g.
    /// </remarks>
     public enum SrpGroup
    {
        /// <summary>1024-bit, g=2, ~80-bit security. Deprecated, legacy only.</summary>
        Rfc5054_1024 = 1,

        /// <summary>1536-bit, g=2, ~90-bit security. Minimum for legacy systems.</summary>
        Rfc5054_1536 = 2,

        /// <summary>2048-bit, g=2, ~112-bit security. Recommended baseline.</summary>
        Rfc5054_2048 = 3,

        /// <summary>3072-bit, g=5, ~128-bit security. Preferred for long-term.</summary>
        Rfc5054_3072 = 4,

        /// <summary>4096-bit, g=5, ~156-bit security. High-security environments.</summary>
        Rfc5054_4096 = 5,

        /// <summary>6144-bit, g=5, ~192-bit security. Specialized high-assurance.</summary>
        Rfc5054_6144 = 6,

        /// <summary>8192-bit, g=19, ~256-bit security. Experimental, extremely slow.</summary>
        Rfc5054_8192 = 7,
    }
}