using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Crossdyne.Security.Abstractions;
using Crossdyne.Security.Utilities;

namespace Crossdyne.Security.Tests
{
    public class SrpEncodingTests
    {
        #region TestData

        private static SrpContext CreateTestContext() => new()
        {
            N = BigInteger.Parse(
                "0EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576" +
                "D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1" +
                "5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC" +
                "68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
                NumberStyles.HexNumber),
            G = 2,
            HashAlgorithmName = HashAlgorithmName.SHA256,
            ModulusSize = 128,
            HashSize = 32
        };

        private static byte[] ComputeM1Expected(SrpContext ctx, BigInteger A, BigInteger B, byte[] K, string identity, byte[] salt)
        {
            byte[] nBytes = SrpEncoding.ToModulusBytes(ctx, ctx.N);
            byte[] gBytes = SrpEncoding.ToModulusBytes(ctx, ctx.G);
            byte[] hashN = SHA256.HashData(nBytes);
            byte[] hashG = SHA256.HashData(gBytes);

            byte[] xorNg = new byte[hashN.Length];
            for (int i = 0; i < hashN.Length; i++)
                xorNg[i] = (byte)(hashN[i] ^ hashG[i]);

            byte[] hashI = SHA256.HashData(Encoding.UTF8.GetBytes(identity));
            byte[] aBytes = SrpEncoding.ToModulusBytes(ctx, A);
            byte[] bBytes = SrpEncoding.ToModulusBytes(ctx, B);

            return SHA256.HashData(
                xorNg.Concat(hashI).Concat(salt).Concat(aBytes).Concat(bBytes).Concat(K).ToArray());
        }

        #endregion

        #region ComputeM1

        [Fact]
        public void ComputeM1_WithKnownInputs_ReturnsExpectedHash()
        {
            // Arrange: тестовый контекст с RFC 5054 1024-bit параметрами
            var ctx = new SrpContext
            {
                N = BigInteger.Parse(
                    "0EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576" +
                    "D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1" +
                    "5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC" +
                    "68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
                    NumberStyles.HexNumber),
                G = 2,
                HashAlgorithmName = HashAlgorithmName.SHA256,
                ModulusSize = 128,
                HashSize = 32,
            };

            BigInteger A = 42;
            BigInteger B = 12345;
            byte[] sessionKeyK = SHA256.HashData(Encoding.UTF8.GetBytes("test_session_key_seed"));
            string identity = "alice";
            byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

            string expectedM1Base64 = "C78M3tWpa2qpbWLQdBsoEkLP6dz7vaPFwnHmVHAIGic=";

            byte[] actualM1 = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK, identity, salt);

            Assert.Equal(expectedM1Base64, Convert.ToBase64String(actualM1));
        }

        [Fact]
        public void ComputeM1_WithSwappedAAndB_ProducesDifferentHash()
        {
            // Arrange: тестовый контекст с RFC 5054 1024-bit параметрами
            var ctx = new SrpContext
            {
                N = BigInteger.Parse(
                    "0EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576" +
                    "D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1" +
                    "5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC" +
                    "68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
                    NumberStyles.HexNumber),
                G = 2,
                HashAlgorithmName = HashAlgorithmName.SHA256,
                ModulusSize = 128,
                HashSize = 32,
            };

            BigInteger A = 42;
            BigInteger B = 12345;
            byte[] sessionKeyK = SHA256.HashData(Encoding.UTF8.GetBytes("test_session_key_seed"));
            string identity = "alice";
            byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

            string expectedM1Base64 = "C78M3tWpa2qpbWLQdBsoEkLP6dz7vaPFwnHmVHAIGic=";

            byte[] actualM1 = SrpEncoding.ComputeM1(ctx, B, A, sessionKeyK, identity, salt);

            Assert.NotEqual(expectedM1Base64, Convert.ToBase64String(actualM1));
        }

        [Fact]
        public void ComputeM1_WithSaltAndKSwapped_ProducesDifferentHash()
        {
            // Arrange: тестовый контекст с RFC 5054 1024-bit параметрами
            var ctx = new SrpContext
            {
                N = BigInteger.Parse(
                    "0EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576" +
                    "D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1" +
                    "5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC" +
                    "68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
                    NumberStyles.HexNumber),
                G = 2,
                HashAlgorithmName = HashAlgorithmName.SHA256,
                ModulusSize = 128,
                HashSize = 32,
            };

            BigInteger A = 42;
            BigInteger B = 12345;
            byte[] sessionKeyK = SHA256.HashData(Encoding.UTF8.GetBytes("test_session_key_seed"));
            string identity = "alice";
            byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

            string expectedM1Base64 = "C78M3tWpa2qpbWLQdBsoEkLP6dz7vaPFwnHmVHAIGic=";

            byte[] actualM1 = SrpEncoding.ComputeM1(ctx, A, B, salt, identity, sessionKeyK);

            Assert.NotEqual(expectedM1Base64, Convert.ToBase64String(actualM1));
        }

        [Fact]
        public void ComputeM1_FirstBlockIsXorOfHashNAndHashG()
        {
            // Arrange: тот же контекст и входные данные
            var ctx = new SrpContext
            {
                N = BigInteger.Parse(
                    "0EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576" +
                    "D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1" +
                    "5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC" +
                    "68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3",
                    NumberStyles.HexNumber),
                G = 2,
                HashAlgorithmName = HashAlgorithmName.SHA256,
                ModulusSize = 128,
                HashSize = 32
            };

            BigInteger A = 42;
            BigInteger B = 12345;
            byte[] sessionKeyK = SHA256.HashData(Encoding.UTF8.GetBytes("test_session_key_seed"));
            string identity = "alice";
            byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

            // Act
            byte[] actualM1 = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK, identity, salt);

            // ---- Ручной пересчёт двух вариантов первого блока ----

            byte[] nBytes = SrpEncoding.ToModulusBytes(ctx, ctx.N);
            byte[] gBytes = SrpEncoding.ToModulusBytes(ctx, ctx.G);

            byte[] hashN = SHA256.HashData(nBytes);
            byte[] hashG = SHA256.HashData(gBytes);

            // Правильно: H(N) ⊕ H(g)
            byte[] xorNg = new byte[hashN.Length];
            for (int i = 0; i < hashN.Length; i++)
                xorNg[i] = (byte)(hashN[i] ^ hashG[i]);

            // Ошибочно: H(N) || H(g) — так делать нельзя
            byte[] concatNg = hashN.Concat(hashG).ToArray();

            // Остальные блоки одинаковы для обоих вариантов
            byte[] hashI = SHA256.HashData(Encoding.UTF8.GetBytes(identity));
            byte[] aBytes = SrpEncoding.ToModulusBytes(ctx, A);
            byte[] bBytes = SrpEncoding.ToModulusBytes(ctx, B);

            byte[] expectedM1WithXor = SHA256.HashData(
                xorNg.Concat(hashI).Concat(salt).Concat(aBytes).Concat(bBytes).Concat(sessionKeyK).ToArray());

            byte[] expectedM1WithConcat = SHA256.HashData(
                concatNg.Concat(hashI).Concat(salt).Concat(aBytes).Concat(bBytes).Concat(sessionKeyK).ToArray());

            // Assert
            Assert.Equal(expectedM1WithXor, actualM1);          // да, используем XOR
            Assert.NotEqual(expectedM1WithConcat, actualM1);    // и точно не конкатенацию
        }

        [Fact]
        public void ComputeM1_WithSmallA_PadsLeadingZerosToModulusSize()
        {
            var ctx = CreateTestContext();
            BigInteger A = 1;
            BigInteger B = 12345;
            byte[] sessionKeyK = SHA256.HashData(Encoding.UTF8.GetBytes("test_session_key_seed"));
            string identity = "alice";
            byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

            byte[] actual = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK, identity, salt);
            byte[] expected = ComputeM1Expected(ctx, A, B, sessionKeyK, identity, salt);

            // Если ComputeM1 использует A без padding'а (1 байт вместо 128), хэш будет другим
            Assert.Equal(expected, actual);

            // Дополнительная страховка: явно считаем "неправильный" вариант с raw 1 байтом для A
            byte[] nBytes = SrpEncoding.ToModulusBytes(ctx, ctx.N);
            byte[] gBytes = SrpEncoding.ToModulusBytes(ctx, ctx.G);
            byte[] hashN = SHA256.HashData(nBytes);
            byte[] hashG = SHA256.HashData(gBytes);
            byte[] xorNg = new byte[hashN.Length];
            for (int i = 0; i < hashN.Length; i++) xorNg[i] = (byte)(hashN[i] ^ hashG[i]);
            byte[] hashI = SHA256.HashData(Encoding.UTF8.GetBytes(identity));
            byte[] bBytes = SrpEncoding.ToModulusBytes(ctx, B);
            byte[] wrongA = new byte[] { 1 }; // raw, без padding'а
            byte[] wrongM1 = SHA256.HashData(xorNg.Concat(hashI).Concat(salt).Concat(wrongA).Concat(bBytes).Concat(sessionKeyK).ToArray());

            Assert.NotEqual(wrongM1, actual);
        }

        [Fact]
        public void ComputeM1_WithExactModulusSizeA_DoesNotTruncate()
        {
            var ctx = CreateTestContext();
            // N-1 занимает ровно 128 байт (старший бит 1, BigInteger не отбрасывает ничего)
            BigInteger A = ctx.N - 1;
            BigInteger B = 12345;
            byte[] sessionKeyK = SHA256.HashData(Encoding.UTF8.GetBytes("test_session_key_seed"));
            string identity = "alice";
            byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

            byte[] actual = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK, identity, salt);
            byte[] expected = ComputeM1Expected(ctx, A, B, sessionKeyK, identity, salt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public void ComputeM1_BPaddedToModulusSize()
        {
            var ctx = CreateTestContext();
            BigInteger A = 42;
            BigInteger B = 1; // маленькое B
            byte[] sessionKeyK = SHA256.HashData(Encoding.UTF8.GetBytes("test_session_key_seed"));
            string identity = "alice";
            byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

            byte[] actual = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK, identity, salt);
            byte[] expected = ComputeM1Expected(ctx, A, B, sessionKeyK, identity, salt);

            Assert.Equal(expected, actual);

            // Страховка: явно считаем с raw 1-байтовым B
            byte[] nBytes = SrpEncoding.ToModulusBytes(ctx, ctx.N);
            byte[] gBytes = SrpEncoding.ToModulusBytes(ctx, ctx.G);
            byte[] hashN = SHA256.HashData(nBytes);
            byte[] hashG = SHA256.HashData(gBytes);
            byte[] xorNg = new byte[hashN.Length];
            for (int i = 0; i < hashN.Length; i++) xorNg[i] = (byte)(hashN[i] ^ hashG[i]);
            byte[] hashI = SHA256.HashData(Encoding.UTF8.GetBytes(identity));
            byte[] aBytes = SrpEncoding.ToModulusBytes(ctx, A);
            byte[] wrongB = new byte[] { 1 };
            byte[] wrongM1 = SHA256.HashData(
                xorNg.Concat(hashI).Concat(salt).Concat(aBytes).Concat(wrongB).Concat(sessionKeyK).ToArray());

            Assert.NotEqual(wrongM1, actual);
        }

        [Fact]
        public void ComputeM1_SessionKeyKUsedAsRawBytesWithoutPadding()
        {
            var ctx = CreateTestContext();
            BigInteger A = 42;
            BigInteger B = 12345;
            string identity = "alice";
            byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

            // K длиной 32 байта (выход SHA-256), явно меньше ModulusSize (128)
            byte[] sessionKeyK = SHA256.HashData(Encoding.UTF8.GetBytes("my_session_key"));

            byte[] actual = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK, identity, salt);
            byte[] expected = ComputeM1Expected(ctx, A, B, sessionKeyK, identity, salt);

            Assert.Equal(expected, actual);

            // Страховка: если бы K допаддился нулями до ModulusSize, хэш изменился бы
            byte[] wrongK = new byte[ctx.ModulusSize];
            Buffer.BlockCopy(sessionKeyK, 0, wrongK, ctx.ModulusSize - sessionKeyK.Length, sessionKeyK.Length);
            byte[] wrongM1 = ComputeM1Expected(ctx, A, B, wrongK, identity, salt);

            Assert.NotEqual(wrongM1, actual);
        }

        [Fact]
        public void ComputeM1_IdentityHashedAsUtf8()
        {
            var ctx = CreateTestContext();
            BigInteger A = 42;
            BigInteger B = 12345;
            byte[] sessionKeyK = SHA256.HashData(Encoding.UTF8.GetBytes("test_session_key_seed"));
            byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

            // Содержит символ за пределами ASCII — UTF-8 и UTF-16 дадут разные байты
            string identity = "naïve";

            byte[] actual = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK, identity, salt);

            // Expected: UTF-8 (правильно)
            byte[] expected = ComputeM1Expected(ctx, A, B, sessionKeyK, identity, salt);
            Assert.Equal(expected, actual);

            // Wrong: UTF-16 LE (как если бы кто-то ошибочно использовал Encoding.Unicode)
            byte[] nBytes = SrpEncoding.ToModulusBytes(ctx, ctx.N);
            byte[] gBytes = SrpEncoding.ToModulusBytes(ctx, ctx.G);
            byte[] hashN = SHA256.HashData(nBytes);
            byte[] hashG = SHA256.HashData(gBytes);
            byte[] xorNg = new byte[hashN.Length];
            for (int i = 0; i < hashN.Length; i++) xorNg[i] = (byte)(hashN[i] ^ hashG[i]);

            byte[] wrongHashI = SHA256.HashData(Encoding.Unicode.GetBytes(identity));
            byte[] aBytes = SrpEncoding.ToModulusBytes(ctx, A);
            byte[] bBytes = SrpEncoding.ToModulusBytes(ctx, B);
            byte[] wrongM1 = SHA256.HashData(
                xorNg.Concat(wrongHashI).Concat(salt).Concat(aBytes).Concat(bBytes).Concat(sessionKeyK).ToArray());

            Assert.NotEqual(wrongM1, actual);
        }

        [Fact]
        public void ComputeM1_IdentityIsCaseSensitive()
        {
            var ctx = CreateTestContext();
            BigInteger A = 42;
            BigInteger B = 12345;
            byte[] sessionKeyK = SHA256.HashData(Encoding.UTF8.GetBytes("test_session_key_seed"));
            byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

            byte[] m1Lower = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK, "alice", salt);
            byte[] m1Upper = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK, "Alice", salt);

            Assert.NotEqual(m1Lower, m1Upper);
        }

        [Fact]
        public void ComputeM1_WithEmptyIdentity_ProducesValidHash()
        {
            var ctx = CreateTestContext();
            BigInteger A = 42;
            BigInteger B = 12345;
            byte[] sessionKeyK = SHA256.HashData(Encoding.UTF8.GetBytes("test_session_key_seed"));
            byte[] salt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

            byte[] actual = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK, string.Empty, salt);
            byte[] expected = ComputeM1Expected(ctx, A, B, sessionKeyK, string.Empty, salt);

            Assert.Equal(expected, actual);
        }

        [Fact]
        public void ComputeM1_WithEmptySalt_ProducesValidHash()
        {
            var ctx = CreateTestContext();
            BigInteger A = 42;
            BigInteger B = 12345;
            byte[] sessionKeyK = SHA256.HashData(Encoding.UTF8.GetBytes("test_session_key_seed"));
            string identity = "alice";

            byte[] actual = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK, identity, Array.Empty<byte>());
            byte[] expected = ComputeM1Expected(ctx, A, B, sessionKeyK, identity, Array.Empty<byte>());

            Assert.Equal(expected, actual);
        }

        [Fact]
        public void ComputeM1_WithLeadingZeroSalt_ProducesValidHash()
        {
            var ctx = CreateTestContext();
            BigInteger A = 42;
            BigInteger B = 12345;
            byte[] sessionKeyK = SHA256.HashData(Encoding.UTF8.GetBytes("test_session_key_seed"));
            string identity = "alice";

            // Salt начинается с 0x00 — проверяем, что ведущий ноль не теряется
            byte[] salt = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

            byte[] actual = SrpEncoding.ComputeM1(ctx, A, B, sessionKeyK, identity, salt);
            byte[] expected = ComputeM1Expected(ctx, A, B, sessionKeyK, identity, salt);

            Assert.Equal(expected, actual);

            // Страховка: если бы salt случайно пропустили через TrimStart(0) или BigInteger,
            // хэш изменился бы
            byte[] wrongSalt = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]; // без ведущего нуля
            byte[] wrongM1 = ComputeM1Expected(ctx, A, B, sessionKeyK, identity, wrongSalt);

            Assert.NotEqual(wrongM1, actual);
        }

        #endregion
    }
}