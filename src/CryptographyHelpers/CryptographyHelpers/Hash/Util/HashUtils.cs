using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Security.Authentication;

namespace CryptographyHelpers.Hash
{
    public static class HashUtils
    {
        public static readonly IDictionary<HashAlgorithmType, int> HashAlgorithmOutputBitsSize = new ConcurrentDictionary<HashAlgorithmType, int>()
        {
            [HashAlgorithmType.Md5] = 128,
            [HashAlgorithmType.Sha1] = 160,
            [HashAlgorithmType.Sha256] = 256,
            [HashAlgorithmType.Sha384] = 384,
            [HashAlgorithmType.Sha512] = 512,
        };

        public static readonly IDictionary<HashAlgorithmType, int> HashAlgorithmOutputBytesSize = new ConcurrentDictionary<HashAlgorithmType, int>()
        {
            [HashAlgorithmType.Md5] = HashAlgorithmOutputBitsSize[HashAlgorithmType.Md5] / Constants.BitsPerByte,
            [HashAlgorithmType.Sha1] = HashAlgorithmOutputBitsSize[HashAlgorithmType.Sha1] / Constants.BitsPerByte,
            [HashAlgorithmType.Sha256] = HashAlgorithmOutputBitsSize[HashAlgorithmType.Sha256] / Constants.BitsPerByte,
            [HashAlgorithmType.Sha384] = HashAlgorithmOutputBitsSize[HashAlgorithmType.Sha384] / Constants.BitsPerByte,
            [HashAlgorithmType.Sha512] = HashAlgorithmOutputBitsSize[HashAlgorithmType.Sha512] / Constants.BitsPerByte,
        };
    }
}