using CryptographyHelpers.Encoding;
using CryptographyHelpers.Encoding.Enums;
using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.Extensions;
using CryptographyHelpers.HMAC.Results;
using CryptographyHelpers.Options;
using CryptographyHelpers.Resources;
using System;

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


        HMACResult VerifyHMAC(string stringToVerifyHMAC, string key, string verificationHMACString, EncodingType keyAndVerificationHMACStringEncodingType, SeekOptions seekOptions)
        {
            if (string.IsNullOrWhiteSpace(stringToVerifyHMAC))
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_InputStringRequired,
                };
            }

            if (string.IsNullOrWhiteSpace(key))
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_InputKeyStringRequired,
                };
            }

            if (string.IsNullOrWhiteSpace(verificationHMACString))
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_VerificationHMACStringRequired,
                };
            }

            try
            {
                var stringToVerifyHMACBytes = stringToVerifyHMAC.ToUTF8Bytes();
                var keyBytes = keyAndVerificationHMACStringEncodingType == EncodingType.Hexadecimal
                    ? Hexadecimal.DecodeString(key)
                    : Base64.DecodeString(key);
                var verificationHMACBytes = keyAndVerificationHMACStringEncodingType == EncodingType.Hexadecimal
                    ? Hexadecimal.DecodeString(verificationHMACString)
                    : Base64.DecodeString(verificationHMACString);

                return VerifyHMAC(stringToVerifyHMACBytes, keyBytes, verificationHMACBytes, seekOptions);
            }
            catch (Exception ex)
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        HMACResult VerifyHMAC(byte[] bytesToVerifyHMAC, byte[] key, byte[] verificationHMACBytes);

        HMACResult VerifyHMAC(byte[] bytesToVerifyHMAC, byte[] key, byte[] verificationHMACBytes, SeekOptions seekOptions);


        HMACResult VerifyFileHMAC(string filePathToVerifyHMAC, string key, string verificationHMACString, EncodingType keyAndVerificationHMACStringEncodingType, LongSeekOptions seekOptions);

        HMACResult VerifyFileHMAC(string filePathToVerifyHMAC, byte[] key, byte[] verificationHMACBytes, LongSeekOptions seekOptions);
    }
}