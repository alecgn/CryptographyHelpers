using CryptographyHelpers.Encoding;
using CryptographyHelpers.EventHandlers;

namespace CryptographyHelpers.Hash
{
    public interface IHash
    {
        event OnProgressHandler OnComputeFileHashProgress;

        HashResult ComputeHash(string stringToComputeHash);

        HashResult ComputeHash(string stringToComputeHash, EncodingType outputEncodingType);

        HashResult ComputeHash(string stringToComputeHash, EncodingType outputEncodingType, OffsetOptions offsetOptions);

        HashResult ComputeHash(byte[] bytesToComputeHash);

        HashResult ComputeHash(byte[] bytesToComputeHash, EncodingType outputEncodingType);

        HashResult ComputeHash(byte[] bytesToComputeHash, EncodingType outputEncodingType, OffsetOptions offsetOptions);


        HashResult ComputeFileHash(string fileToComputeHash);

        HashResult ComputeFileHash(string fileToComputeHash, EncodingType outputEncodingType);

        HashResult ComputeFileHash(string fileToComputeHash, EncodingType outputEncodingType, LongOffsetOptions offsetOptions);



        HashResult VerifyHash(string stringToVerifyHash, string verificationHashString);

        HashResult VerifyHash(string stringToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType);

        HashResult VerifyHash(string stringToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType, OffsetOptions offsetOptions);

        HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes);

        HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes, OffsetOptions offsetOptions);


        HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString);

        HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType);

        HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType, LongOffsetOptions offsetOptions);

        HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes);

        HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes, LongOffsetOptions offsetOptions);
    }
}
