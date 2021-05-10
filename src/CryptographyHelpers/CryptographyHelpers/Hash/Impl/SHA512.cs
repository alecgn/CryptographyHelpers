namespace CryptographyHelpers.Hash
{
    public class SHA512 : HashBase, IHash
    {
        private const HashAlgorithmType _hashAlgorithmType = HashAlgorithmType.SHA512;

        /// <summary>
        /// Computes the SHA512 hash of an input byte array.
        /// </summary>
        /// <param name="bytesToComputeHash">The input byte array to compute the SHA512 hash.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult ComputeHash(byte[] bytesToComputeHash, int offset = 0, int count = 0)
        {
            return base.ComputeHash(_hashAlgorithmType, bytesToComputeHash, offset, count);
        }

        /// <summary>
        /// Computes the SHA512 hash of an input string.
        /// </summary>
        /// <param name="stringToComputeHash">The input string to compute the SHA512 hash.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult ComputeHash(string stringToComputeHash, int offset = 0, int count = 0)
        {
            return base.ComputeHash(_hashAlgorithmType, stringToComputeHash, offset, count);
        }

        /// <summary>
        /// Computes the SHA512 hash of an input file.
        /// </summary>
        /// <param name="filePathToComputeHash">The input file path to compute the SHA512 hash.</param>
        /// <param name="offset">The offset into the FileStream from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the FileStream to read after the offset.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult ComputeFileHash(string filePathToComputeHash, long offset = 0, long count = 0)
        {
            return base.ComputeFileHash(_hashAlgorithmType, filePathToComputeHash, offset, count);
        }

        /// <summary>
        /// Verifies the SHA512 hash of an input byte array.
        /// </summary>
        /// <param name="hashBytes">The pre-computed SHA512 hash byte array.</param>
        /// <param name="bytesToVerifyHash">The input byte array to compute and verify the SHA512 hash.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyHash(byte[] hashBytes, byte[] bytesToVerifyHash, int offset = 0, int count = 0)
        {
            return base.VerifyHash(_hashAlgorithmType, hashBytes, bytesToVerifyHash, offset, count);
        }

        /// <summary>
        /// Verifies the SHA512 hash of an input string.
        /// </summary>
        /// <param name="hashHexadecimalString">The pre-computed SHA512 hash hexadecimal encoded string.</param>
        /// <param name="stringToVerifyHash">The input string to compute and verify the SHA512 hash.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyHash(string hashHexadecimalString, string stringToVerifyHash, int offset = 0, int count = 0)
        {
            return base.VerifyHash(_hashAlgorithmType, hashHexadecimalString, stringToVerifyHash, offset, count);
        }

        /// <summary>
        /// Verifies the SHA512 of an input file.
        /// </summary>
        /// <param name="hashHexadecimalString">The pre-computed SHA512 hash hexadecimal encoded string.</param>
        /// <param name="filePathToVerifyHash">The input file path to compute and verify the SHA512 hash.</param>
        /// <param name="offset">The offset into the FileStream from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the FileStream to read after the offset.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyFileHash(string hashHexadecimalString, string filePathToVerifyHash, long offset = 0, long count = 0)
        {
            return base.VerifyFileHash(_hashAlgorithmType, hashHexadecimalString, filePathToVerifyHash, offset, count);
        }

        /// <summary>
        /// Verifies the SHA512 of an input file.
        /// </summary>
        /// <param name="hashBytes">The pre-computed SHA512 hash byte array.</param>
        /// <param name="filePathToVerifyHash">The input file path to compute and verify the SHA512 hash.</param>
        /// <param name="offset">The offset into the FileStream from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the FileStream to read after the offset.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyFileHash(byte[] hashBytes, string filePathToVerifyHash, long offset = 0, long count = 0)
        {
            return base.VerifyFileHash(_hashAlgorithmType, hashBytes, filePathToVerifyHash, offset, count);
        }
    }
}
