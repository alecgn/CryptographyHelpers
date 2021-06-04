using CryptographyHelpers.HMAC.Enums;
using System.Collections.Concurrent;
using System.Collections.Generic;

namespace CryptographyHelpers.HMAC.Util
{
    public static class HMACUtil
    {
        public static readonly IDictionary<HMACAlgorithmType, int> HMACSizeMapper = new ConcurrentDictionary<HMACAlgorithmType, int>()
        {
            [HMACAlgorithmType.HMACMD5] = 128,
            [HMACAlgorithmType.HMACSHA1] = 160,
            [HMACAlgorithmType.HMACSHA256] = 256,
            [HMACAlgorithmType.HMACSHA384] = 384,
            [HMACAlgorithmType.HMACSHA512] = 512,
        };
    }
}