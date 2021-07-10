using CryptographyHelpers.EventHandlers;
using System;

namespace CryptographyHelpers.Hash
{
    public interface IHash : IDisposable
    {
        event OnProgressHandler OnComputeFileHashProgress;

        HashResult ComputeHash(byte[] bytesToComputeHash, OffsetOptions? offsetOptions = null);

        HashResult ComputeHash(string textToComputeHash, OffsetOptions? offsetOptions = null);

        HashResult ComputeFileHash(string fileToComputeHash, LongOffsetOptions? offsetOptions = null);

        HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes, OffsetOptions? offsetOptions = null);

        HashResult VerifyHash(string textToVerifyHash, string encodedVerificationHashString, OffsetOptions? offsetOptions = null);

        HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes, LongOffsetOptions? offsetOptions = null);

        HashResult VerifyFileHash(string fileToVerifyHash, string encodedVerificationHashString, LongOffsetOptions? offsetOptions = null);
    }
}