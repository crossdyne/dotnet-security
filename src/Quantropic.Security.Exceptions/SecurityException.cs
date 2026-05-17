namespace Quantropic.Security.Exceptions
{
    /// <summary>
    /// Base exception for all Quantropic Security library errors.
    /// </summary>
    public class SecurityException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityException"/> class.
        /// </summary>
        public SecurityException() : base() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public SecurityException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecurityException"/> class with a specified error message and a reference to the inner exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="inner">The exception that is the cause of the current exception.</param>
        public SecurityException(string message, Exception inner) : base(message, inner) { }
    }
}