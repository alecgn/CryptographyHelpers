namespace CryptographyHelpers.Hash
{
    public class MD5 : HashBase
    {
        private const HashAlgorithmType _hashAlgorithmType = HashAlgorithmType.MD5;

        /// <summary>
        /// Computes the MD5 hash of an input byte array.
        /// </summary>
        /// <param name="bytesToComputeHash">The input byte array to compute the MD5 hash.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult ComputeHash(byte[] bytesToComputeHash, int offset = 0, int count = 0)
        {
            return base.ComputeHash(_hashAlgorithmType, bytesToComputeHash, offset, count);
        }

        /// <summary>
        /// Computes the MD5 hash of an input string.
        /// </summary>
        /// <param name="stringToComputeHash">The input string to compute the MD5 hash.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult ComputeHash(string stringToComputeHash, int offset = 0, int count = 0)
        {
            return base.ComputeHash(_hashAlgorithmType, stringToComputeHash, offset, count);
        }

        /// <summary>
        /// Computes the MD5 hash of an input file.
        /// </summary>
        /// <param name="filePathToComputeHash">The input file path to compute the MD5 hash.</param>
        /// <param name="offset">The offset into the FileStream from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the FileStream to read after the offset.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult ComputeFileHash(string filePathToComputeHash, long offset = 0, long count = 0)
        {
            return base.ComputeFileHash(_hashAlgorithmType, filePathToComputeHash, offset, count);
        }


        /// <summary>
        /// Verifies the MD5 hash of an input byte array.
        /// </summary>
        /// <param name="hashBytes">The pre-computed MD5 hash byte array.</param>
        /// <param name="bytesToVerifyHash">The input byte array to compute and verify the MD5 hash.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyHash(byte[] hashBytes, byte[] bytesToVerifyHash, int offset = 0, int count = 0)
        {
            return base.VerifyHash(_hashAlgorithmType, hashBytes, bytesToVerifyHash, offset, count);
        }

        /// <summary>
        /// Verifies the MD5 hash of an input string.
        /// </summary>
        /// <param name="hashHexString">The pre-computed MD5 hash hexadecimal encoded string.</param>
        /// <param name="stringToVerifyHash">The input string to compute and verify the MD5 hash.</param>
        /// <param name="offset">The offset into the byte array from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the array to read after the offset.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyHash(string hashHexString, string stringToVerifyHash, int offset = 0, int count = 0)
        {
            return base.VerifyHash(_hashAlgorithmType, hashHexString, stringToVerifyHash, offset, count);
        }

        /// <summary>
        /// Verifies the MD5 of an input file.
        /// </summary>
        /// <param name="hashHexString">The pre-computed MD5 hash hexadecimal encoded string.</param>
        /// <param name="filePathToVerifyHash">The input file path to compute and verify the MD5 hash.</param>
        /// <param name="offset">The offset into the FileStream from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the FileStream to read after the offset.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyFileHash(string hashHexString, string filePathToVerifyHash, long offset = 0, long count = 0)
        {
            return base.VerifyFileHash(_hashAlgorithmType, hashHexString, filePathToVerifyHash, offset, count);
        }

        /// <summary>
        /// Verifies the MD5 of an input file.
        /// </summary>
        /// <param name="hashBytes">The pre-computed MD5 hash byte array.</param>
        /// <param name="filePathToVerifyHash">The input file path to compute and verify the MD5 hash.</param>
        /// <param name="offset">The offset into the FileStream from wich to begin reading data.</param>
        /// <param name="count">The number of bytes in the FileStream to read after the offset.</param>
        /// <returns>GenericHashResult</returns>
        public GenericHashResult VerifyFileHash(byte[] hashBytes, string filePathToVerifyHash, long offset = 0, long count = 0)
        {
            return base.VerifyFileHash(_hashAlgorithmType, hashBytes, filePathToVerifyHash, offset, count);
        }
    }
}
