using Crossdyne.Security.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Crossdyne.Security.Srp.Server
{
    /// <summary>
    /// Extension methods for registering Crossdyne SRP server services with <see cref="IServiceCollection"/>.
    /// </summary>
    public static class SrpServerServiceCollectionExtensions
    {
        /// <summary>
        /// Adds Crossdyne SRP server services to the specified <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <returns>The same <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddCrossdyneSrpServer(this IServiceCollection services)
        {
            services.TryAddSingleton<ISrpServer, SrpServerService>();

            return services;
        }   
    }
}