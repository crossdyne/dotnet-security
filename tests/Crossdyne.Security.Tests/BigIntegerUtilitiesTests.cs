using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Crossdyne.Security.Utilities;

namespace Crossdyne.Security.Tests
{
    public class BigIntegerUtilitiesTests
    {
        #region ToFixedLengthBytes
        
        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(-100)]
        public void ToFixedLengthBytes_NonPositiveLength_ThrowsArgumentException(int length)
        {
            Assert.Throws<ArgumentException>(() => BigIntegerUtilities.ToFixedLengthBytes(BigInteger.One, length));
        }

        [Fact]
        public void ToFixedLengthBytes_ValueTooLarge_ThrowsArgumentException()
        {
            var value = new BigInteger(0x010000);
            var ex = Assert.Throws<ArgumentException>(
                () => BigIntegerUtilities.ToFixedLengthBytes(value, 2));
            Assert.Equal("value", ex.ParamName);
        }

        [Theory]
        [InlineData(0x00, 1, new byte[] { 0x00 })]
        [InlineData(0xAB, 1, new byte[] { 0xAB })]
        [InlineData(0x0102, 2, new byte[] { 0x01, 0x02 })]
        [InlineData(0x01020304, 4, new byte[] { 0x01, 0x02, 0x03, 0x04 })]
        public void ToFixedLengthBytes_ExactLength_ReturnsAsIs(int value, int length, byte[] expected)
        {
            byte[] result = BigIntegerUtilities.ToFixedLengthBytes(new BigInteger(value), length);
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData(0x00, 4, new byte[] { 0x00, 0x00, 0x00, 0x00 })]
        [InlineData(0x01, 4, new byte[] { 0x00, 0x00, 0x00, 0x01 })]
        [InlineData(0xABCD, 4, new byte[] { 0x00, 0x00, 0xAB, 0xCD })]
        [InlineData(0x010203, 8, new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03 })]
        public void ToFixedLengthBytes_SmallerValue_PadsWithLeadingZeros(int value, int length, byte[] expected)
        {
            byte[] result = BigIntegerUtilities.ToFixedLengthBytes(new BigInteger(value), length);
            Assert.Equal(expected, result);
        }

        [Fact]
        public void ToFixedLengthBytes_MaxValueForLength_FitsExactly()
        {
            // 0xFFFF — максимум для 2 байт unsigned
            byte[] result = BigIntegerUtilities.ToFixedLengthBytes(new BigInteger(0xFFFF), 2);
            Assert.Equal(new byte[] { 0xFF, 0xFF }, result);
        }

        [Fact]
        public void ToFixedLengthBytes_OneByteOverLimit_Throws()
        {
            // 0x10000 — уже 3 байта, не влезает в 2
            Assert.Throws<ArgumentException>(() => BigIntegerUtilities.ToFixedLengthBytes(new BigInteger(0x10000), 2));
        }

        [Fact]
        public void ToFixedLengthBytes_VeryLargeNumber_Works()
        {
            var value = BigInteger.Pow(2, 255); // 32 байта
            byte[] result = BigIntegerUtilities.ToFixedLengthBytes(value, 32);
            Assert.Equal(32, result.Length);
            Assert.Equal(0x80, result[0]); // старший бит выставлен
        }

        [Fact]
        public void ToFixedLengthBytes_NegativeValue_Throws()
        {
            // В .NET это вызовет исключение внутри ToByteArray
            Assert.ThrowsAny<Exception>(() => BigIntegerUtilities.ToFixedLengthBytes(new BigInteger(-1), 4));
        }

        [Fact]
        public void ToFixedLengthBytes_OrderIsBigEndian()
        {
            byte[] result = BigIntegerUtilities.ToFixedLengthBytes(new BigInteger(0x0102), 2);
            Assert.Equal(0x01, result[0]);
            Assert.Equal(0x02, result[1]);
        }

        #endregion

        #region DecodeBase64ToBytes

        [Fact]
        public void DecodeBase64ToBytes_Decode_Success()
        {
            var bytes = new byte[3] { 0x01, 0x02, 0x03 };
            string base64 = Convert.ToBase64String(bytes);
            var decodeBytes = BigIntegerUtilities.DecodeBase64ToBytes(base64);

            Assert.Equal(bytes, decodeBytes);
        }

        [Fact]
        public void DecodeBase64ToBytes_NullBase64_ThrowException()
        {
            Assert.Throws<ArgumentNullException>(() => BigIntegerUtilities.DecodeBase64ToBytes(""));
        }

        #endregion

        #region FromBase64

        [Fact]
        public void FromBase64_ValidBase64_ReturnsCorrectBigInteger()
        {
            // Arrange: 0x0102 = 258, big-endian
            byte[] bytes = new byte[] { 0x01, 0x02 };
            string base64 = Convert.ToBase64String(bytes);

            BigInteger result = BigIntegerUtilities.FromBase64(base64);

            Assert.Equal(new BigInteger(0x0102), result);
        }

        [Fact]
        public void FromBase64_Zero_ReturnsZero()
        {
            // Arrange: BigInteger.Zero = 1 байт 0x00 → Base64 "AA=="
            string base64 = Convert.ToBase64String(new byte[] { 0x00 });

            BigInteger result = BigIntegerUtilities.FromBase64(base64);

            Assert.Equal(BigInteger.Zero, result);
        }

        [Fact]
        public void FromBase64_Zero_ThrowsArgumentNullException()
        {
            Assert.Throws<ArgumentNullException>(() =>
            {
                var base64 = Convert.ToBase64String(new byte[0]);
                BigInteger result = BigIntegerUtilities.FromBase64(base64);
            });
        }
    
        [Fact]
        public void FromBase64_LargeNumber_ReturnsCorrectValue()
        {
            byte[] bytes = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
            string base64 = Convert.ToBase64String(bytes);

            BigInteger result = BigIntegerUtilities.FromBase64(base64);

            Assert.Equal(new BigInteger(bytes, isUnsigned: true, isBigEndian: true), result);
        }

        [Theory]
        [InlineData("not-base64!!!")]  // содержит '!', невалидный символ
        [InlineData("123$")]           // '$' не из алфавита base64
        [InlineData("====")]           // валидные символы, но некорректная структура
        public void FromBase64_InvalidBase64_ThrowsFormatException(string invalidBase64)
        {
            Assert.Throws<FormatException>(() => BigIntegerUtilities.FromBase64(invalidBase64));
        }

        #endregion

        #region Hash

        [Fact]
        public void Hash_KnownSha256Vector_ReturnsExpectedValue()
        {
           byte[] data = Encoding.ASCII.GetBytes("abc");
           byte[] expectedBytes = Convert.FromHexString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
           var expected = new BigInteger(expectedBytes, isUnsigned: true, isBigEndian: true);

           var actual = BigIntegerUtilities.Hash(HashAlgorithmName.SHA256, data);

           Assert.Equal(expected, actual);
        }

        [Fact]
        public void Hash_MultipleBuffers_EquivalentToConcatenatedHash()
        {
            var buf1 = new byte[] { 1, 2, 3 };
            var buf2 = new byte[] { 4, 5 , 6 };
            var concatenated = new byte[] { 1, 2, 3, 4, 5, 6 };

            var formParts = BigIntegerUtilities.Hash(HashAlgorithmName.SHA256, buf1, buf2);
            var fromSingle = BigIntegerUtilities.Hash(HashAlgorithmName.SHA256, concatenated);

            Assert.Equal(formParts, fromSingle);
        }

        [Fact]
        public void Hash_DifferentAlgorithms_ProduceDifferentResults()
        {
            var buf1 = new byte[] { 1, 2, 3 };
            var buf2 = new byte[] { 4, 5 , 6 };

            BigInteger hash256 = BigIntegerUtilities.Hash(HashAlgorithmName.SHA256, buf1, buf2);
            BigInteger hash512 = BigIntegerUtilities.Hash(HashAlgorithmName.SHA512, buf1, buf2);

            Assert.NotEqual(hash256, hash512);
        }

        [Fact]
        public void Hash_EmptyInput_ReturnsEmptyHash()
        {
            byte[] expectedBytes = Convert.FromHexString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
            var expected = new BigInteger(expectedBytes, isUnsigned: true, isBigEndian: true);

            BigInteger actual = BigIntegerUtilities.Hash(HashAlgorithmName.SHA256, Array.Empty<byte>());

            Assert.Equal(expected, actual);
        }

        [Fact]
        public void Hash_IsDeterministic()
        {
            var buf1 = new byte[] { 1, 2, 3 };
            var buf2 = new byte[] { 4, 5 , 6 };

            BigInteger hashOne = BigIntegerUtilities.Hash(HashAlgorithmName.SHA256, buf1, buf2);
            BigInteger hashTwo = BigIntegerUtilities.Hash(HashAlgorithmName.SHA256, buf1, buf2);

            Assert.Equal(hashOne, hashTwo);
        }

        #endregion

        #region ComputeHash

        [Fact]
        public void ComputeHash_KnownSha256Vector_ReturnsExpectedValue()
        {
           byte[] data = Encoding.ASCII.GetBytes("abc");
           byte[] expectedBytes = Convert.FromHexString("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");

           var actual = BigIntegerUtilities.ComputeHash(HashAlgorithmName.SHA256, data);

           Assert.Equal(expectedBytes, actual);
        }

        [Fact]
        public void ComputeHash_MultipleBuffers_EquivalentToConcatenatedHash()
        {
            var buf1 = new byte[] { 1, 2, 3 };
            var buf2 = new byte[] { 4, 5 , 6 };
            var concatenated = new byte[] { 1, 2, 3, 4, 5, 6 };

            byte[] formParts = BigIntegerUtilities.ComputeHash(HashAlgorithmName.SHA256, buf1, buf2);
            byte[] fromSingle = BigIntegerUtilities.ComputeHash(HashAlgorithmName.SHA256, concatenated);

            Assert.Equal(formParts, fromSingle);
        }

        [Fact]
        public void ComputeHash_DifferentAlgorithms_ProduceDifferentResults()
        {
            var buf1 = new byte[] { 1, 2, 3 };
            var buf2 = new byte[] { 4, 5 , 6 };

            byte[] hash256 = BigIntegerUtilities.ComputeHash(HashAlgorithmName.SHA256, buf1, buf2);
            byte[] hash512 = BigIntegerUtilities.ComputeHash(HashAlgorithmName.SHA512, buf1, buf2);

            Assert.NotEqual(hash256, hash512);
        }

        [Fact]
        public void ComputeHash_EmptyInput_ReturnsEmptyHash()
        {
            byte[] expectedBytes = Convert.FromHexString("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

            byte[] actual = BigIntegerUtilities.ComputeHash(HashAlgorithmName.SHA256, Array.Empty<byte>());

            Assert.Equal(expectedBytes, actual);
        }

        [Fact]
        public void ComputeHash_IsDeterministic()
        {
            var buf1 = new byte[] { 1, 2, 3 };
            var buf2 = new byte[] { 4, 5 , 6 };

            byte[] hashOne = BigIntegerUtilities.ComputeHash(HashAlgorithmName.SHA256, buf1, buf2);
            byte[] hashTwo = BigIntegerUtilities.ComputeHash(HashAlgorithmName.SHA256, buf1, buf2);

            Assert.Equal(hashOne, hashTwo);
        }


        #endregion
    }
}