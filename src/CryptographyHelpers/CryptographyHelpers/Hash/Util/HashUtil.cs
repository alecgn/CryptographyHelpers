using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.Hash
{
    [ExcludeFromCodeCoverage]
    public static class HashUtil
    {
        public static readonly IDictionary<HashAlgorithmType, int> HashAlgorithmOutputBitsSizeMapper = new ConcurrentDictionary<HashAlgorithmType, int>()
        {
            [HashAlgorithmType.MD5] = 128,
            [HashAlgorithmType.SHA1] = 160,
            [HashAlgorithmType.SHA256] = 256,
            [HashAlgorithmType.SHA384] = 384,
            [HashAlgorithmType.SHA512] = 512,
        };

        public static readonly IDictionary<HashAlgorithmType, int> HashAlgorithmOutputBytesSizeMapper = new ConcurrentDictionary<HashAlgorithmType, int>()
        {
            [HashAlgorithmType.MD5] = HashAlgorithmOutputBitsSizeMapper[HashAlgorithmType.MD5] / Constants.BitsPerByte,
            [HashAlgorithmType.SHA1] = HashAlgorithmOutputBitsSizeMapper[HashAlgorithmType.SHA1] / Constants.BitsPerByte,
            [HashAlgorithmType.SHA256] = HashAlgorithmOutputBitsSizeMapper[HashAlgorithmType.SHA256] / Constants.BitsPerByte,
            [HashAlgorithmType.SHA384] = HashAlgorithmOutputBitsSizeMapper[HashAlgorithmType.SHA384] / Constants.BitsPerByte,
            [HashAlgorithmType.SHA512] = HashAlgorithmOutputBitsSizeMapper[HashAlgorithmType.SHA512] / Constants.BitsPerByte,
        };
    }
}