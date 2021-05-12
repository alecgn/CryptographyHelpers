using CryptographyHelpers.Encoding;

namespace CryptographyHelpers.Hash
{
    public class SHA512 : HashBase, IHash
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA512;

        public GenericHashResult ComputeHash(
            byte[] bytesToComputeHash,
            SeekOptions seekOptions,
            HexadecimalEncodingOptions hexadecimalOutputEncodingOptions)
        {
            return base.ComputeHash(bytesToComputeHash, HashAlgorithm, seekOptions, hexadecimalOutputEncodingOptions);
        }

        public GenericHashResult ComputeHash(byte[] bytesToComputeHash)
        {
            return base.ComputeHash(bytesToComputeHash, HashAlgorithm);
        }

        public GenericHashResult ComputeHash(
            string stringToComputeHash,
            SeekOptions seekOptions,
            HexadecimalEncodingOptions hexadecimalOutputEncodingOptions)
        {
            return base.ComputeHash(stringToComputeHash, HashAlgorithm, seekOptions, hexadecimalOutputEncodingOptions);
        }

        public GenericHashResult ComputeHash(string stringToComputeHash)
        {
            return base.ComputeHash(stringToComputeHash, HashAlgorithm);
        }

        public GenericHashResult ComputeFileHash(
            string fileToComputeHash,
            LongSeekOptions seekOptions,
            HexadecimalEncodingOptions hexadecimalOutputEncodingOptions)
        {
            return base.ComputeFileHash(fileToComputeHash, HashAlgorithm, seekOptions, hexadecimalOutputEncodingOptions);
        }

        public GenericHashResult ComputeFileHash(string fileToComputeHash)
        {
            return base.ComputeFileHash(fileToComputeHash, HashAlgorithm);
        }

        public GenericHashResult VerifyHash(byte[] verificationHashBytes, byte[] bytesToVerifyHash)
        {
            return base.VerifyHash(verificationHashBytes, bytesToVerifyHash, HashAlgorithm);
        }

        public GenericHashResult VerifyHash(string verificationHexadecimalHashString, string stringToVerifyHash)
        {
            return base.VerifyHash(verificationHexadecimalHashString, stringToVerifyHash, HashAlgorithm);
        }

        public GenericHashResult VerifyFileHash(string verificationHexadecimalHashString, string fileToVerifyHash)
        {
            return base.VerifyFileHash(verificationHexadecimalHashString, fileToVerifyHash, HashAlgorithm);
        }

        public GenericHashResult VerifyFileHash(byte[] verificationHashBytes, string fileToVerifyHash)
        {
            return base.VerifyFileHash(verificationHashBytes, fileToVerifyHash, HashAlgorithm);
        }
    }
}