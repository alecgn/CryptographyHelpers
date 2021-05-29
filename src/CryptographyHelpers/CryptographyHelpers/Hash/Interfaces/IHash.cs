using CryptographyHelpers.Encoding.Enums;
using CryptographyHelpers.Hash.EventHandlers;
using CryptographyHelpers.Hash.Results;
using CryptographyHelpers.Options;

namespace CryptographyHelpers.Hash
{
    public interface IHash
    {
        event OnHashProgressHandler OnHashProgress;

        GenericHashResult ComputeHash(string stringToComputeHash);

        GenericHashResult ComputeHash(string stringToComputeHash, SeekOptions seekOptions);

        GenericHashResult ComputeHash(string stringToComputeHash, SeekOptions seekOptions, EncodingType outputEncodingType);

        GenericHashResult ComputeHash(byte[] bytesToComputeHash);

        GenericHashResult ComputeHash(byte[] bytesToComputeHash, SeekOptions seekOptions);

        GenericHashResult ComputeHash(byte[] bytesToComputeHash, SeekOptions seekOptions, EncodingType outputEncodingType);


        GenericHashResult ComputeFileHash(string fileToComputeHash);

        GenericHashResult ComputeFileHash(string fileToComputeHash, LongSeekOptions seekOptions);

        GenericHashResult ComputeFileHash(string fileToComputeHash, LongSeekOptions seekOptions, EncodingType outputEncodingType);



        GenericHashResult VerifyHash(string stringToVerifyHash, string verificationHashString);

        GenericHashResult VerifyHash(string stringToVerifyHash, string verificationHashString, SeekOptions seekOptions);

        GenericHashResult VerifyHash(string stringToVerifyHash, string verificationHashString, SeekOptions seekOptions, EncodingType verificationHashStringEncodingType);

        GenericHashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes);

        GenericHashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes, SeekOptions seekOptions);


        GenericHashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString);

        GenericHashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, LongSeekOptions seekOptions);

        GenericHashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, LongSeekOptions seekOptions, EncodingType verificationHashStringEncodingType);

        GenericHashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes);

        GenericHashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes, LongSeekOptions seekOptions);
    }
}
