using CryptographyHelpers.Encoding;

namespace CryptographyHelpers.Hash
{
    public interface IHashBase
    {
        public event OnHashProgressHandler OnHashProgress;

        public GenericHashResult ComputeHash(
            byte[] bytesToComputeHash,
            HashAlgorithmType hashAlgorithmType,
            IntPositionOptions positionOptions,
            HexadecimalEncodingOptions hexadecimalOutputEncodingOptions);

        public GenericHashResult ComputeHash(
            string stringToComputeHash,
            HashAlgorithmType hashAlgorithmType,
            IntPositionOptions positionOptions,
            HexadecimalEncodingOptions hexadecimalOutputEncodingOptions);

        public GenericHashResult ComputeFileHash(
            string fileToComputeHash,
            HashAlgorithmType hashAlgorithmType,
            LongPositionOptions positionOptions,
            HexadecimalEncodingOptions hexadecimalOutputEncodingOptions);


        public GenericHashResult VerifyHash(
            byte[] hashBytes,
            byte[] bytesToVerifyHash,
            HashAlgorithmType hashAlgorithmType,
            IntPositionOptions positionOptions);

        public GenericHashResult VerifyHash(
            string hashHexadecimalString,
            string stringToVerifyHash,
            HashAlgorithmType hashAlgorithmType,
            IntPositionOptions positionOptions);

        public GenericHashResult VerifyFileHash(
            string hashHexadecimalString,
            string fileToVerifyHash,
            HashAlgorithmType hashAlgorithmType,
            LongPositionOptions positionOptions);

        public GenericHashResult VerifyFileHash(
            byte[] hashBytes,
            string fileToVerifyHash,
            HashAlgorithmType hashAlgorithmType,
            LongPositionOptions positionOptions);
    }
}