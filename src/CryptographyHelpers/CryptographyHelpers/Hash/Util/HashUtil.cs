using CryptographyHelpers.Hash.Enums;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace CryptographyHelpers.Hash.Util
{
    public static class HashUtil
    {
        public static readonly IDictionary<HashAlgorithmType, int> HashOutputSizeDictionary = new ConcurrentDictionary<HashAlgorithmType, int>()
        {
            [HashAlgorithmType.MD5] = 128,
            [HashAlgorithmType.SHA1] = 160,
            [HashAlgorithmType.SHA256] = 256,
            [HashAlgorithmType.SHA384] = 384,
            [HashAlgorithmType.SHA512] = 512,
        };
    }
}