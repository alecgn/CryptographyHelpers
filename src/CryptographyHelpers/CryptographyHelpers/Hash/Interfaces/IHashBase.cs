using CryptographyHelpers.Encoding;

namespace CryptographyHelpers.Hash
{
    public interface IHashBase
    {
        event OnHashProgressHandler OnHashProgress;

        GenericHashResult ComputeHash(
            byte[] bytesToComputeHash,
            HashAlgorithmType hashAlgorithmType,
            SeekOptions positionOptions,
            HexadecimalEncodingOptions hexadecimalOutputEncodingOptions);

        GenericHashResult ComputeHash(
            byte[] bytesToComputeHash,
            HashAlgorithmType hashAlgorithmType);

        GenericHashResult ComputeHash(
            string stringToComputeHash,
            HashAlgorithmType hashAlgorithmType,
            SeekOptions positionOptions,
            HexadecimalEncodingOptions hexadecimalOutputEncodingOptions);

        GenericHashResult ComputeHash(
            string stringToComputeHash,
            HashAlgorithmType hashAlgorithmType);

        GenericHashResult ComputeFileHash(
            string fileToComputeHash,
            HashAlgorithmType hashAlgorithmType,
            LongSeekOptions positionOptions,
            HexadecimalEncodingOptions hexadecimalOutputEncodingOptions);

        GenericHashResult ComputeFileHash(
            string fileToComputeHash,
            HashAlgorithmType hashAlgorithmType);

        GenericHashResult VerifyHash(
            byte[] hashBytes,
            byte[] bytesToVerifyHash,
            HashAlgorithmType hashAlgorithmType);

        GenericHashResult VerifyHash(
            string hashHexadecimalString,
            string stringToVerifyHash,
            HashAlgorithmType hashAlgorithmType);

        GenericHashResult VerifyFileHash(
            string hashHexadecimalString,
            string fileToVerifyHash,
            HashAlgorithmType hashAlgorithmType);

        GenericHashResult VerifyFileHash(
            byte[] hashBytes,
            string fileToVerifyHash,
            HashAlgorithmType hashAlgorithmType);
    }
}