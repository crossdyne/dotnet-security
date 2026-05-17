namespace Quantropic.Security.Exceptions
{
    /// <summary>
    /// Exception thrown when decryption fails due to authentication tag mismatch or corrupted data.
    /// </summary>
    public class DecryptionException : SecurityException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="DecryptionException"/> class with a default message.
        /// </summary>
        public DecryptionException() : base("Decrypted failed: authentication tag mismatch or corrupted data.") { }

        /// <summary>
        /// Initializes a new instance of the <see cref="DecryptionException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public DecryptionException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="DecryptionException"/> class with a specified error message and a reference to the inner exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="inner">The exception that is the cause of the current exception.</param>
        public DecryptionException(string message, Exception inner) : base(message, inner) { }
    }
}