namespace Quantropic.Security.Exceptions
{
    /// <summary>
    /// Exception thrown when SRP (Secure Remote Password) verification fails due to corrupted verifier or protocol mismatch.
    /// </summary>
    public class SrpVerificationException : SecurityException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SrpVerificationException"/> class with a default message.
        /// </summary>
        public SrpVerificationException() : base("Внутренняя ошибка данных: верификатор поврежден.") { }

        /// <summary>
        /// Initializes a new instance of the <see cref="SrpVerificationException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public SrpVerificationException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="SrpVerificationException"/> class with a specified error message and a reference to the inner exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="inner">The exception that is the cause of the current exception.</param>
        public SrpVerificationException(string message, Exception inner) : base(message, inner) { }
    }
}