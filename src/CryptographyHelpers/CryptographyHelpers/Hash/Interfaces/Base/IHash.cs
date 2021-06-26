using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.Options;
using System;

namespace CryptographyHelpers.Hash
{
    public interface IHash : IDisposable
    {
        event OnProgressHandler OnComputeFileHashProgress;

        HashResult ComputeHash(string stringToComputeHash);

        HashResult ComputeHash(string stringToComputeHash, OffsetOptions offsetOptions);

        HashResult ComputeHash(byte[] bytesToComputeHash);

        HashResult ComputeHash(byte[] bytesToComputeHash, OffsetOptions offsetOptions);

        HashResult VerifyHash(string stringToVerifyHash, string encodedVerificationHashString);

        HashResult VerifyHash(string stringToVerifyHash, string encodedVerificationHashString, OffsetOptions offsetOptions);

        HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes);

        HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes, OffsetOptions offsetOptions);

        HashResult ComputeFileHash(string fileToComputeHash);

        HashResult ComputeFileHash(string fileToComputeHash, LongOffsetOptions offsetOptions);

        HashResult VerifyFileHash(string fileToVerifyHash, string encodedVerificationHashString);

        HashResult VerifyFileHash(string fileToVerifyHash, string encodedVerificationHashString, LongOffsetOptions offsetOptions);

        HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes);

        HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes, LongOffsetOptions offsetOptions);
    }
}