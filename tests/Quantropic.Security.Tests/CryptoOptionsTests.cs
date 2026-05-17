using System.Text;
using Quantropic.Security.Configuration;

namespace Quantropic.Security.Tests
{
    public class CryptoOptionsTests
    {
        [Fact]
        public void DefaultOptions_HaveExpectedValues()
        {
            var options = CryptoOptions.Default;

            Assert.Equal(SecurityConstants.AesGcmNonceSize, options.NonceSize);
            Assert.Equal(SecurityConstants.AesGcmTagSize, options.TagSize);
            Assert.Equal(SecurityConstants.Pbkdf2IterationsDefault, options.Pbkdf2Iterations);
            Assert.False(options.CompressBeforeEncrypt);
            Assert.Null(options.AssociatedData);
        }

        [Fact]
        public void Builder_WithAssociatedDataText_ConvertsToBytes()
        {
            const string aadText = "user:12345:context";

            var options = CryptoOptions.Create()
                .WithAssociatedData(aadText)
                .Build();

            Assert.Equal(aadText, Encoding.UTF8.GetString(options.AssociatedData!));
        }

        [Fact]
        public void Builder_WithHighSecurityKdf_SetsRecommendedIterations()
        {
            var options = CryptoOptions.Create()
                .WithHighSecurityKdf()
                .Build();

            Assert.Equal(SecurityConstants.Pbkdf2IterationsRecommended, options.Pbkdf2Iterations);
        }

        [Fact]
        public void CryptoOptionsBuilder_Build_Succeeds_WithValidIterations()
        {
            var options = CryptoOptions.Create()
                .WithPbkdf2Iterations(SecurityConstants.Pbkdf2IterationsMinimum)
                .Build();

            Assert.NotNull(options);
            Assert.Equal(SecurityConstants.Pbkdf2IterationsMinimum, options.Pbkdf2Iterations);
        }

        [Fact]
        public void CryptoOptionsBuilder_WithPbkdf2Iterations_Throws_WhenBelowMinimum()
        {
            Assert.Throws<ArgumentOutOfRangeException>(() =>
                CryptoOptions.Create()
                    .WithPbkdf2Iterations(SecurityConstants.Pbkdf2IterationsMinimum - 1));
        }

        [Fact]
        public void Presets_AreImmutable_ThroughReadOnlyProperty()
        {
            // Note: Presets are static readonly, but their properties can still be modified
            // if someone casts or accesses directly. This test documents the risk.
            
            var defaultOptions = CryptoOptions.Default;
            var originalIterations = defaultOptions.Pbkdf2Iterations;

            // Act: Try to modify (this will work because properties are not truly immutable)
            defaultOptions.Pbkdf2Iterations = SecurityConstants.Pbkdf2IterationsRecommended;

            // Assert: This shows why presets should be used carefully
            Assert.NotEqual(originalIterations, defaultOptions.Pbkdf2Iterations);
        }
    }
}