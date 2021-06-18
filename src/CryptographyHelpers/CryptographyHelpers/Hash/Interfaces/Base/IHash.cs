using CryptographyHelpers.Encoding;
using CryptographyHelpers.EventHandlers;

namespace CryptographyHelpers.Hash
{
    public interface IHash
    {
        event OnProgressHandler OnComputeFileHashProgress;

        HashResult ComputeHash(string stringToComputeHash);

        HashResult ComputeHash(string stringToComputeHash, EncodingType outputEncodingType);

        HashResult ComputeHash(string stringToComputeHash, EncodingType outputEncodingType, RangeOptions rangeOptions);

        HashResult ComputeHash(byte[] bytesToComputeHash);

        HashResult ComputeHash(byte[] bytesToComputeHash, EncodingType outputEncodingType);

        HashResult ComputeHash(byte[] bytesToComputeHash, EncodingType outputEncodingType, RangeOptions rangeOptions);


        HashResult ComputeFileHash(string fileToComputeHash);

        HashResult ComputeFileHash(string fileToComputeHash, EncodingType outputEncodingType);

        HashResult ComputeFileHash(string fileToComputeHash, EncodingType outputEncodingType, LongRangeOptions rangeOptions);



        HashResult VerifyHash(string stringToVerifyHash, string verificationHashString);

        HashResult VerifyHash(string stringToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType);

        HashResult VerifyHash(string stringToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType, RangeOptions rangeOptions);

        HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes);

        HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes, RangeOptions rangeOptions);


        HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString);

        HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType);

        HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType, LongRangeOptions rangeOptions);

        HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes);

        HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes, LongRangeOptions rangeOptions);
    }
}
