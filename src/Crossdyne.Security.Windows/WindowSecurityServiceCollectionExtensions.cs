using Crossdyne.Security.Abstractions;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Crossdyne.Security.Windows
{
    /// <summary>
    /// Extension methods for registering Crossdyne Windows security services with <see cref="IServiceCollection"/>.
    /// </summary>
    public static class WindowSecurityServiceCollectionExtensions
    {
        /// <summary>
        /// Adds Crossdyne Windows security services to the specified <see cref="IServiceCollection"/>.
        /// </summary>
        /// <param name="services">The <see cref="IServiceCollection"/> to add services to.</param>
        /// <returns>The same <see cref="IServiceCollection"/> so that additional calls can be chained.</returns>
        public static IServiceCollection AddCrossdyneWindowSecurity(this IServiceCollection services)
        {
            services.TryAddSingleton<IDeviceIdentityService, DeviceIdentityService>();
            services.TryAddSingleton<ISecureTokenStorage, WindowSecureTokenStorage>();

            return services;
        }
    }
}