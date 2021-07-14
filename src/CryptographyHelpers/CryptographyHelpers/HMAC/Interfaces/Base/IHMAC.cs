using CryptographyHelpers.EventHandlers;
using System;

namespace CryptographyHelpers.HMAC
{
    public interface IHMAC : IDisposable
    {
        event OnProgressHandler OnComputeFileHMACProgress;

        HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, OffsetOptions? offsetOptions = null);

        HMACResult ComputeTextHMAC(string textToComputeHMAC, OffsetOptions? offsetOptions = null);

        HMACResult ComputeFileHMAC(string filePathToComputeHMAC, LongOffsetOptions? offsetOptions = null);

        HMACResult VerifyHMAC(byte[] bytesToVerifyHMAC, byte[] verificationHMACBytes, OffsetOptions? offsetOptions = null);

        HMACResult VerifyTextHMAC(string textToVerifyHMAC, string encodedVerificationHMACString, OffsetOptions? offsetOptions = null);

        HMACResult VerifyFileHMAC(string filePathToVerifyHMAC, byte[] verificationHMACBytes, LongOffsetOptions? offsetOptions = null);

        HMACResult VerifyFileHMAC(string filePathToVerifyHMAC, string encodedVerificationHMACString, LongOffsetOptions offsetOptions);
    }
}