using Crossdyne.Security.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Crossdyne.Security.Srp.Client
{
    /// <summary>
    /// Extension methods for registering Crossdyne SRP client services with <see cref="IServiceCollection"/>.
    /// </summary>
    public static class SrpClientServiceCollectionExtensions
    {
        /// <summary>
        /// Adds Crossdyne SRP client services to the specified <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <returns>The same <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddCrossdyneSrpClient(this IServiceCollection services)
        {
            services.TryAddSingleton<ISrpClient, SrpClientService>();
            services.TryAddSingleton<ISrpKeyDerivationService, SrpKeyDerivationService>();
            return services;
        }
    }
}