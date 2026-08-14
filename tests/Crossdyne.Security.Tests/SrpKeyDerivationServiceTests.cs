using System.Text;
using Crossdyne.Security.Configuration;
using Crossdyne.Security.Exceptions;
using Crossdyne.Security.Srp.Client;

namespace Crossdyne.Security.Tests
{
    public class SrpKeyDerivationServiceTests
    {
         private readonly SrpKeyDerivationService _sut = new();
        private readonly byte[] _validSalt = new byte[16];

        // Подставьте реальные значения из ваших enum/реестров
        private const SrpGroup ValidGroup = SrpGroup.Rfc5054_3072; 
        private const CryptoVersion ValidVersion = CryptoVersion.V1;

        [Fact]
        public void DeriveAuthHashForSrp_ValidInputs_ReturnsNonEmptyHash()
        {
            byte[] result = _sut.DeriveAuthHashForSrp("user", "password", _validSalt, ValidGroup, ValidVersion);

            Assert.NotNull(result);
            Assert.True(result.Length > 0);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void DeriveAuthHashForSrp_InvalidIdentity_ThrowsArgumentException(string? identity)
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                _sut.DeriveAuthHashForSrp(identity!, "password", _validSalt, ValidGroup, ValidVersion));

            Assert.Equal("identity", ex.ParamName);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        [InlineData("   ")]
        public void DeriveAuthHashForSrp_InvalidPassword_ThrowsArgumentException(string? password)
        {
            var ex = Assert.Throws<ArgumentException>(() =>
                _sut.DeriveAuthHashForSrp("user", password!, _validSalt, ValidGroup, ValidVersion));

            Assert.Equal("password", ex.ParamName);
        }

        [Fact]
        public void DeriveAuthHashForSrp_NullSalt_ThrowsInvalidKeyException()
        {
            Assert.Throws<InvalidKeyException>(() =>
                _sut.DeriveAuthHashForSrp("user", "password", null!, ValidGroup, ValidVersion));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(15)]
        public void DeriveAuthHashForSrp_ShortSalt_ThrowsInvalidKeyException(int saltLength)
        {
            byte[] shortSalt = new byte[saltLength];

            Assert.Throws<InvalidKeyException>(() =>
                _sut.DeriveAuthHashForSrp("user", "password", shortSalt, ValidGroup, ValidVersion));
        }

        [Fact]
        public void DeriveAuthHashForSrp_SameInputsProduceSameOutput()
        {
            byte[] salt = Encoding.UTF8.GetBytes("fixed-salt-12345");

            byte[] hash1 = _sut.DeriveAuthHashForSrp("alice", "secret", salt, ValidGroup, ValidVersion);
            byte[] hash2 = _sut.DeriveAuthHashForSrp("alice", "secret", salt, ValidGroup, ValidVersion);

            Assert.Equal(hash1, hash2);
        }

        [Fact]
        public void DeriveAuthHashForSrp_DifferentIdentitiesProduceDifferentOutput()
        {
            byte[] salt = Encoding.UTF8.GetBytes("fixed-salt-12345");

            byte[] hash1 = _sut.DeriveAuthHashForSrp("alice", "secret", salt, ValidGroup, ValidVersion);
            byte[] hash2 = _sut.DeriveAuthHashForSrp("bob", "secret", salt, ValidGroup, ValidVersion);

            Assert.NotEqual(hash1, hash2);
        }
    }
}