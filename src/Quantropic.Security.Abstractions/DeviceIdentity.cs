namespace Quantropic.Security.Abstractions
{
    /// <summary>
    /// Represents a unique device identity for client identification and tracking.
    /// Used to associate authentication sessions with specific devices and detect
    /// suspicious activities based on device fingerprints.
    /// </summary>
    public class DeviceIdentity
    {
        /// <summary>
        /// Gets or sets the unique identifier for the device.
        /// Automatically generated as a new GUID by default.
        /// Used to track and identify specific devices across sessions.
        /// </summary>
        public string DeviceId { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Gets or sets the cryptographic hash of the device's fingerprint.
        /// The fingerprint is typically generated from various device attributes
        /// (browser, OS, screen resolution, installed fonts, etc.) to create
        /// a unique and consistent identifier for the device.
        /// </summary>
        public string FingerprintHash { get; set; } = null!;
    }
}