using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Win32;
using Quantropic.Security.Abstractions;

namespace Quantropic.Security.Windows
{
    /// <summary>
    /// Windows-specific implementation of <see cref="IDeviceIdentityService"/>.
    /// Generates, stores, and retrieves a persistent device identity using DPAPI for encryption.
    /// The identity includes a unique device ID and a hash of hardware/software fingerprint.
    /// </summary>
    public class DeviceIdentityService : IDeviceIdentityService
    {
         /// <summary>
        /// Initializes a new instance of the <see cref="DeviceIdentityService"/> class.
        /// </summary>
        /// <param name="folderName">The name of the subfolder within %LocalAppData% where device identity data will be stored.</param>
        /// <remarks>
        /// The constructor builds the full storage path by combining 
        /// <see cref="Environment.SpecialFolder.LocalApplicationData"/> with the provided <paramref name="folderName"/>,
        /// and sets the identity file path to <c>device.dat</c> within that folder.
        /// </remarks>
        public DeviceIdentityService(string folderName)
        {
            _folderPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), folderName);
            _filePath = Path.Combine(_folderPath, "device.dat");
        }

        private readonly string _folderPath;
        private readonly string _filePath;

        /// <summary>
        /// Retrieves the existing device identity from encrypted storage, or creates and saves a new one if none exists or if decryption fails.
        /// </summary>
        /// <returns>A <see cref="DeviceIdentity"/> instance representing the current device.</returns>
        public async Task<DeviceIdentity> GetOrCreateAsync()
        {
             if (File.Exists(_filePath))
            {
                try
                {
                    var encryptedData = await File.ReadAllBytesAsync(_filePath);
                    var decrypted = ProtectedData.Unprotect(encryptedData, null, DataProtectionScope.CurrentUser);
                    var json = Encoding.UTF8.GetString(decrypted);

                    var identity = JsonSerializer.Deserialize<DeviceIdentity>(json);

                    if (identity != null)
                        return identity;
                }
                catch
                {
                    
                }
            }

            return await CreateAndSaveNewAsync();
        }

        /// <summary>
        /// Creates a new <see cref="DeviceIdentity"/> with a fresh device ID and fingerprint hash, then persists it to encrypted storage.
        /// </summary>
        /// <returns>The newly created <see cref="DeviceIdentity"/>.</returns>
        private async Task<DeviceIdentity> CreateAndSaveNewAsync()
        {
            var fingerprint = GenerateRawFingerprint();
            var hashBytes = SHA256.HashData(Encoding.UTF8.GetBytes(fingerprint));
            var hashString = Convert.ToBase64String(hashBytes);

            var identity = new DeviceIdentity
            {
                DeviceId = Guid.NewGuid().ToString(),
                FingerprintHash = hashString
            };

            await SaveAsync(identity);

            return identity;
        }

        /// <summary>
        /// Serializes and encrypts a <see cref="DeviceIdentity"/> using Windows DPAPI, then writes it to the configured file path.
        /// </summary>
        /// <param name="identity">The device identity to persist.</param>
        private async Task SaveAsync(DeviceIdentity identity)
        {
            var json = JsonSerializer.Serialize(identity);
            var bytes = Encoding.UTF8.GetBytes(json);
            var encrypted = ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser);

            Directory.CreateDirectory(_folderPath);
            await File.WriteAllBytesAsync(_filePath, encrypted);
        }

        /// <summary>
        /// Generates a raw device fingerprint string based on hardware and OS characteristics.
        /// This value is not stored directly; only its SHA-256 hash is retained in the identity.
        /// </summary>
        /// <returns>A concatenated string of device attributes.</returns>
        private static string GenerateRawFingerprint()
        {
            var machineGuid = GetMachineGuid(); 
            var osVersion = Environment.OSVersion.ToString();
            var processorCount = Environment.ProcessorCount.ToString();
            var totalMemory = GC.GetGCMemoryInfo().TotalAvailableMemoryBytes / (1024 * 1024 * 1024);

            return $"{machineGuid}-{osVersion}-{processorCount}-{totalMemory}";
        }

        /// <summary>
        /// Retrieves the Windows MachineGuid from the registry, or generates a fallback GUID if unavailable.
        /// </summary>
        /// <returns>The machine GUID string.</returns>
        private static string GetMachineGuid()
        {
            try
            {
                using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography", false);

                return key?.GetValue("MachineGuid")?.ToString() ?? Guid.NewGuid().ToString();
            }
            catch
            {
                return Guid.NewGuid().ToString();
            }
        }
    }
}