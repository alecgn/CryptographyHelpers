using CryptographyHelpers.Encoding.Enums;
using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.Hash.Results;
using CryptographyHelpers.Options;

namespace CryptographyHelpers.Hash
{
    public interface IHash
    {
        event OnProgressHandler OnComputeFileHashProgress;

        HashResult ComputeHash(string stringToComputeHash);

        HashResult ComputeHash(string stringToComputeHash, EncodingType outputEncodingType);

        HashResult ComputeHash(string stringToComputeHash, EncodingType outputEncodingType, SeekOptions seekOptions);

        HashResult ComputeHash(byte[] bytesToComputeHash);

        HashResult ComputeHash(byte[] bytesToComputeHash, EncodingType outputEncodingType);

        HashResult ComputeHash(byte[] bytesToComputeHash, EncodingType outputEncodingType, SeekOptions seekOptions);


        HashResult ComputeFileHash(string fileToComputeHash);

        HashResult ComputeFileHash(string fileToComputeHash, EncodingType outputEncodingType);

        HashResult ComputeFileHash(string fileToComputeHash, EncodingType outputEncodingType, LongSeekOptions seekOptions);



        HashResult VerifyHash(string stringToVerifyHash, string verificationHashString);

        HashResult VerifyHash(string stringToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType);

        HashResult VerifyHash(string stringToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType, SeekOptions seekOptions);

        HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes);

        HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes, SeekOptions seekOptions);


        HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString);

        HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType);

        HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType, LongSeekOptions seekOptions);

        HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes);

        HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes, LongSeekOptions seekOptions);
    }
}
