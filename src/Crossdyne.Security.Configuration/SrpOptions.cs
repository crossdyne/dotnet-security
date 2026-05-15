using System.Numerics;
using System.Security.Cryptography;

namespace Crossdyne.Security.Configuration
{
    /// <summary>
    /// 
    /// </summary>
    public class SrpOptions
    {
        /// <summary>
        /// 
        /// </summary>
        public SrpGroup Group { get; init; } = SrpGroup.Rfc5054_3072;

        /// <summary>
        /// 
        /// </summary>
        public HashAlgorithmName HashAlgorithmName { get; init; } = HashAlgorithmName.SHA256;

        /// <summary>
        /// 
        /// </summary>
        public int SaltSize { get; init; } = 32;

        /// <summary>
        /// 
        /// </summary>
        public BigInteger N => SrpGroupParams.GetN(Group);

        /// <summary>
        /// 
        /// </summary>
        public int G => (int)SrpGroupParams.GetG(Group);

        /// <summary>
        /// 
        /// </summary>
        public int ModulusSize => (int)((N.GetBitLength() + 7) / 8);

        /// <summary>
        /// 
        /// </summary>
        public BigInteger ComputeK()
        {
            using var hash = IncrementalHash.CreateHash(HashAlgorithmName);
            
            byte[] nBytes = ToFixedLengthBytes(N, ModulusSize);
            byte[] gBytes = ToFixedLengthBytes(new BigInteger(G), ModulusSize);

            var ngBytes = Concat(nBytes, gBytes);
            hash.AppendData(ngBytes);
            var kBytes = hash.GetHashAndReset();

            return new BigInteger(kBytes, isUnsigned: true, isBigEndian: true);
        }

        /// <summary>
        /// 
        /// </summary>
        private static byte[] Concat(byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];

            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);

            return result;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="value"></param>
        /// <param name="length"></param>
        /// <returns></returns>
        /// <exception cref="ArgumentException"></exception>
        private static byte[] ToFixedLengthBytes(BigInteger value, int length)
        {
            if (length <= 0) throw 
                new ArgumentException("The length must be positive.", nameof(length));

            byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);

            if (bytes.Length == length)
                return bytes;

            byte[] result = new byte[length];

            if (bytes.Length > length)
                Buffer.BlockCopy(bytes, bytes.Length - length, result, 0, length);
            else
                Buffer.BlockCopy(bytes, 0, result, length - bytes.Length, bytes.Length);

            return result;
        }
    }
}