using System.Text;
using Crossdyne.Security.Configuration;

namespace Crossdyne.Security.Tests
{
    public class CryptoOptionsTests
    {
        [Fact]
        public void DefaultOptions_HaveExpectedValues()
        {
            var options = AesGcmOptions.Default;

            Assert.Equal(SecurityConstants.AesGcmNonceSize, options.NonceSize);
            Assert.Equal(SecurityConstants.AesGcmTagSize, options.TagSize);
            Assert.Null(options.AssociatedData);
        }

        [Fact]
        public void Builder_WithAssociatedDataText_ConvertsToBytes()
        {
            const string aadText = "user:12345:context";

            var options = AesGcmOptions.Create()
                .WithAssociatedData(aadText)
                .Build();

            Assert.Equal(aadText, Encoding.UTF8.GetString(options.AssociatedData!));
        }
    }
}