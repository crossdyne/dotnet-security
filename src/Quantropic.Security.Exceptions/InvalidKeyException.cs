namespace Quantropic.Security.Exceptions
{
    /// <summary>
    /// Exception thrown when a cryptographic key is invalid due to incorrect length or format.
    /// </summary>
    public class InvalidKeyException : SecurityException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidKeyException"/> class with a default message.
        /// </summary>
        public InvalidKeyException() : base("Invalid key: incorrect length or format.") { }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidKeyException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public InvalidKeyException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="InvalidKeyException"/> class with a specified error message and a reference to the inner exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="inner">The exception that is the cause of the current exception.</param>
        public InvalidKeyException(string message, Exception inner) : base(message, inner) { }
    }
}