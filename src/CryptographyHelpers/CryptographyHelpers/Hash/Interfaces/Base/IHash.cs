using CryptographyHelpers.EventHandlers;
using System;

namespace CryptographyHelpers.Hash
{
    public interface IHash : IDisposable
    {
        event OnProgressHandler OnComputeFileHashProgress;

        HashResult ComputeHash(byte[] bytesToComputeHash, OffsetOptions offsetOptions = null);

        HashResult ComputeTextHash(string textToComputeHash, OffsetOptions offsetOptions = null);

        HashResult ComputeFileHash(string filePathToComputeHash, LongOffsetOptions offsetOptions = null);

        HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes, OffsetOptions offsetOptions = null);

        HashResult VerifyTextHash(string textToVerifyHash, string encodedVerificationHashString, OffsetOptions offsetOptions = null);

        HashResult VerifyFileHash(string filePathToVerifyHash, byte[] verificationHashBytes, LongOffsetOptions offsetOptions = null);

        HashResult VerifyFileHash(string filePathToVerifyHash, string encodedVerificationHashString, LongOffsetOptions offsetOptions = null);
    }
}