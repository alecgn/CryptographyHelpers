using CryptographyHelpers.Encoding;
using CryptographyHelpers.EventHandlers;

namespace CryptographyHelpers.HMAC
{
    public interface IHMAC
    {
        event OnProgressHandler OnComputeFileHMACProgress;

        public HMACResult ComputeHMAC(string stringToComputeHMAC);

        HMACResult ComputeHMAC(string stringToComputeHMAC, string key);

        HMACResult ComputeHMAC(string stringToComputeHMAC, string key, EncodingType keyAndOutputEncodingType);

        HMACResult ComputeHMAC(string stringToComputeHMAC, string key, EncodingType keyAndOutputEncodingType, SeekOptions seekOptions);

        HMACResult ComputeHMAC(byte[] bytesToComputeHMAC);

        HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, byte[] key);

        HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, byte[] key, EncodingType outputEncodingType);

        HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, byte[] key, EncodingType outputEncodingType, SeekOptions seekOptions);


        HMACResult ComputeFileHMAC(string filePathToComputeHMAC);

        HMACResult ComputeFileHMAC(string filePathToComputeHMAC, string key);

        HMACResult ComputeFileHMAC(string filePathToComputeHMAC, string key, EncodingType outputEncodingType);

        HMACResult ComputeFileHMAC(string filePathToComputeHMAC, string key, EncodingType keyAndOutputEncodingType, LongSeekOptions seekOptions);

        HMACResult ComputeFileHMAC(string filePathToComputeHMAC, byte[] key);

        HMACResult ComputeFileHMAC(string filePathToComputeHMAC, byte[] key, EncodingType outputEncodingType);

        HMACResult ComputeFileHMAC(string filePathToComputeHMAC, byte[] key, EncodingType outputEncodingType, LongSeekOptions seekOptions);


        HMACResult VerifyHMAC(string stringToVerifyHMAC, string key, string verificationHMACString);

        HMACResult VerifyHMAC(string stringToVerifyHMAC, string key, string verificationHMACString, EncodingType keyAndVerificationHMACStringEncodingType);


        HMACResult VerifyHMAC(string stringToVerifyHMAC, string key, string verificationHMACString, EncodingType keyAndVerificationHMACStringEncodingType, SeekOptions seekOptions);

        HMACResult VerifyHMAC(byte[] bytesToVerifyHMAC, byte[] key, byte[] verificationHMACBytes);

        HMACResult VerifyHMAC(byte[] bytesToVerifyHMAC, byte[] key, byte[] verificationHMACBytes, SeekOptions seekOptions);


        HMACResult VerifyFileHMAC(string filePathToVerifyHMAC, string key, string verificationHMACString, EncodingType keyAndVerificationHMACStringEncodingType, LongSeekOptions seekOptions);

        HMACResult VerifyFileHMAC(string filePathToVerifyHMAC, byte[] key, byte[] verificationHMACBytes, LongSeekOptions seekOptions);
    }
}