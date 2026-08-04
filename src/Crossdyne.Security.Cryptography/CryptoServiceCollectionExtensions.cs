using Crossdyne.Security.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Crossdyne.Security.Cryptography
{
    /// <summary>
    /// Extension methods for registering Crossdyne cryptography services with <see cref="IServiceCollection"/>.
    /// </summary>
    public static class CryptoServiceCollectionExtensions
    {
        /// <summary>
        /// Adds Crossdyne cryptography services to the specified <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <returns>The same <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddCrossdyneCryptography(this IServiceCollection services)
        {
            services.TryAddSingleton<IKeyDerivationService, KeyDerivationService>();
            services.TryAddSingleton<ICryptoService, CryptoService>();

            return services;
        }
    }
}