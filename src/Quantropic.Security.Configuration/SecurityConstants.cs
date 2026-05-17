using System.Globalization;
using System.Numerics;

namespace Quantropic.Security.Configuration
{
    /// <summary>
    /// Security of cryptographic operations
    /// </summary>
    /// <remarks>
    /// <para>Warning: Do not change these values for existing encrypted data.</para>
    /// <para>Changing values will break compatibility with previously encrypted data.</para>
    /// </remarks>
    public static class SecurityConstants
    {
        // === SRP ===

        /// <summary>
        /// The prime modulus (N) used in SRP arithmetic operations.
        /// This is a 3072-bit safe prime from RFC 5054, Group E, providing approximately 128 bits of security.
        /// All modular exponentiations in the protocol are performed modulo this value.
        /// </summary>
        public static readonly BigInteger N = BigInteger.Parse("00AC6BDB41324A9A9BF166DE5E1F403D434A6E1B3B94A7E62AC1211858E002C75AD4455C9D19C0A3180296917A376205164043E20144FF485719D181A99EB574671AC58054457ED444A67032EA17D03AD43464D2397449CA593630A670D90D95A78E846A3C8AF80862098D80F33C42ED7059E75225E0A52718E2379369F65B79680A6560B080092EE71986066735A96A7D42E7597116742B02D3A154471B6A23D84E0D642C790D597A2BB7F5A48F734898BDD138C69493E723491959C1B4BD40C91C1C7924F88D046467A006507E781220A80C55A927906A7C6C9C227E674686DD5D1B855D28F0D604E24586C608630B9A34C4808381A54F0D9080A5F90B60187F", NumberStyles.HexNumber);
     
        /// <summary>
        /// The SRP multiplier parameter (k), computed as k = H(N, g) where H is SHA-256.
        /// This value prevents two-party attacks and is used in the computation of the server's public value B.
        /// Defined per RFC 5054 for the 3072-bit group.
        /// </summary>
        public static readonly BigInteger k = BigInteger.Parse("00D55AE1AEC9F9115621E93E16E5DE4517DF8450D0957024D1256AA32B71E4E412", NumberStyles.HexNumber);
       
        /// <summary>
        /// The generator (g) for the multiplicative group modulo N.
        /// Set to 2, which is a primitive root modulo the prime N defined in RFC 5054.
        /// </summary>
        public const int g = 2;
        
        /// <summary>
        /// The fixed size in bytes for serializing modulus-sized values (N, A, B, S, v).
        /// Set to 384 bytes to accommodate the 3072-bit prime modulus (3072 bits / 8 = 384 bytes).
        /// Ensures consistent big-endian encoding for network transmission and hashing.
        /// </summary>
        public const int ModulusSize = 384;

        // === AES-GCM Parameters ===

        /// <summary>Standard nonce size for AES-GCM (96 bits)</summary>
        public const int AesGcmNonceSize = 12;

        /// <summary>Standard authentication tag size for AES-GCM (128 bits).</summary>
        public const int AesGcmTagSize = 16;
        /// <summary>Minimum allowed tag size (96 bits).</summary>
        public const int AesGcmTagSizeMin = 12;
        /// <summary>Maximum allowed tag size (128 bits).</summary>
        public const int AesGcmTagSizeMax = 16;

        // === Key Parameters ===

        /// <summary>Default key size for AES-256 (256 bits).</summary>
        public const int KeySizeBytes = 32;

        // === KDF Parameters ===

        /// <summary>Default PBKDF2 iterations (balanced security/performance as of 2024).</summary>
        public const int Pbkdf2IterationsDefault = 600_000;

        /// <summary>Recommended PBKDF2 iterations for high-security scenarios.</summary>
        public const int Pbkdf2IterationsRecommended = 1_000_000;
        
        /// <summary>Minimum safe PBKDF2 iterations. Values below this are rejected.</summary>
        public const int Pbkdf2IterationsMinimum = 100_000;
        
    }
}