using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.Hash
{
    [ExcludeFromCodeCoverage]
    public static class HashUtils
    {
        public static readonly IDictionary<HashAlgorithmType, int> HashAlgorithmOutputBitsSize = new ConcurrentDictionary<HashAlgorithmType, int>()
        {
            [HashAlgorithmType.MD5] = 128,
            [HashAlgorithmType.SHA1] = 160,
            [HashAlgorithmType.SHA256] = 256,
            [HashAlgorithmType.SHA384] = 384,
            [HashAlgorithmType.SHA512] = 512,
        };

        public static readonly IDictionary<HashAlgorithmType, int> HashAlgorithmOutputBytesSize = new ConcurrentDictionary<HashAlgorithmType, int>()
        {
            [HashAlgorithmType.MD5] = HashAlgorithmOutputBitsSize[HashAlgorithmType.MD5] / Constants.BitsPerByte,
            [HashAlgorithmType.SHA1] = HashAlgorithmOutputBitsSize[HashAlgorithmType.SHA1] / Constants.BitsPerByte,
            [HashAlgorithmType.SHA256] = HashAlgorithmOutputBitsSize[HashAlgorithmType.SHA256] / Constants.BitsPerByte,
            [HashAlgorithmType.SHA384] = HashAlgorithmOutputBitsSize[HashAlgorithmType.SHA384] / Constants.BitsPerByte,
            [HashAlgorithmType.SHA512] = HashAlgorithmOutputBitsSize[HashAlgorithmType.SHA512] / Constants.BitsPerByte,
        };
    }
}