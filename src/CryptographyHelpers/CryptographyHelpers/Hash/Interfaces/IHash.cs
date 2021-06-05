using CryptographyHelpers.Encoding.Enums;
using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.Hash.Results;
using CryptographyHelpers.Options;

namespace CryptographyHelpers.Hash
{
    public interface IHash
    {
        event OnProgressHandler OnFileHashProgress;

        HashResult ComputeHash(string stringToComputeHash);

        HashResult ComputeHash(string stringToComputeHash, SeekOptions seekOptions);

        HashResult ComputeHash(string stringToComputeHash, SeekOptions seekOptions, EncodingType outputEncodingType);

        HashResult ComputeHash(byte[] bytesToComputeHash);

        HashResult ComputeHash(byte[] bytesToComputeHash, SeekOptions seekOptions);

        HashResult ComputeHash(byte[] bytesToComputeHash, SeekOptions seekOptions, EncodingType outputEncodingType);


        HashResult ComputeFileHash(string fileToComputeHash);

        HashResult ComputeFileHash(string fileToComputeHash, LongSeekOptions seekOptions);

        HashResult ComputeFileHash(string fileToComputeHash, LongSeekOptions seekOptions, EncodingType outputEncodingType);



        HashResult VerifyHash(string stringToVerifyHash, string verificationHashString);

        HashResult VerifyHash(string stringToVerifyHash, string verificationHashString, SeekOptions seekOptions);

        HashResult VerifyHash(string stringToVerifyHash, string verificationHashString, SeekOptions seekOptions, EncodingType verificationHashStringEncodingType);

        HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes);

        HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes, SeekOptions seekOptions);


        HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString);

        HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, LongSeekOptions seekOptions);

        HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, LongSeekOptions seekOptions, EncodingType verificationHashStringEncodingType);

        HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes);

        HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes, LongSeekOptions seekOptions);
    }
}
