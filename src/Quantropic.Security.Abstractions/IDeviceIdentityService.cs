namespace Quantropic.Security.Abstractions
{
    /// <summary>
    /// Provides device identity management services.
    /// </summary>
    public interface IDeviceIdentityService
    {
        /// <summary>
        /// Retrieves the existing device identity or creates a new one if it doesn't exist.
        /// </summary>
        /// <returns>A task that represents the asynchronous operation. The task result contains the device identity.</returns>
        Task<DeviceIdentity> GetOrCreateAsync();
    }
}