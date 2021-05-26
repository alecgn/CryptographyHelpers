using CryptographyHelpers.Hash.EventHandlers;
using CryptographyHelpers.HMAC.Results;
using CryptographyHelpers.Options;

namespace CryptographyHelpers.HMAC
{
    public interface IHMAC
    {
        event OnHashProgressHandler OnHMACProgress;

        HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, SeekOptions seekOptions, byte[] key = null);

        HMACResult ComputeHMAC(string stringToComputeHMAC, SeekOptions seekOptions, byte[] key = null);

        HMACResult ComputeFileHMAC(string filePathToComputeHMAC, LongSeekOptions seekOptions, byte[] key = null);

        HMACResult VerifyHMAC(byte[] hmacBytes, byte[] bytesToVerifyHMAC, SeekOptions seekOptions, byte[] key);

        HMACResult VerifyHMAC(string hmacHexString, string stringToVerifyHMAC, SeekOptions seekOptions, byte[] key);

        HMACResult VerifyFileHMAC(string hmacHexString, string filePathToVerifyHMAC, LongSeekOptions seekOptions, byte[] key);

        HMACResult VerifyFileHMAC(byte[] hmacBytes, string filePathToVerifyHMAC, LongSeekOptions seekOptions, byte[] key);
    }
}