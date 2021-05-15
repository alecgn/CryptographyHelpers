using CryptographyHelpers.Encoding;

namespace CryptographyHelpers.Hash
{
    public interface IHash
    {
        GenericHashResult ComputeHash(byte[] bytesToComputeHash, SeekOptions seekOptions, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions);

        GenericHashResult ComputeHash(byte[] bytesToComputeHash);

        GenericHashResult ComputeHash(string stringToComputeHash, SeekOptions seekOptions, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions);

        GenericHashResult ComputeHash(string stringToComputeHash);

        GenericHashResult ComputeFileHash(string fileToComputeHash, LongSeekOptions seekOptions, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions);

        GenericHashResult ComputeFileHash(string fileToComputeHash);

        GenericHashResult VerifyHash(byte[] verificationHashBytes, byte[] bytesToVerifyHash);

        GenericHashResult VerifyHash(string verificationHexadecimalHashString, string stringToVerifyHash);

        GenericHashResult VerifyFileHash(string verificationHexadecimalHashString, string fileToVerifyHash);

        GenericHashResult VerifyFileHash(byte[] verificationHashBytes, string fileToVerifyHash);
    }
}
