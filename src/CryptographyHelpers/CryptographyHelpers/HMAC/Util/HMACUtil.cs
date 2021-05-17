using System.Collections.Concurrent;
using System.Collections.Generic;

namespace CryptographyHelpers.HMAC
{
    public static class HMACUtil
    {
        public static readonly IDictionary<HMACAlgorithmType, int> HMACLengthMapper = new ConcurrentDictionary<HMACAlgorithmType, int>()
        {
            [HMACAlgorithmType.HMACMD5] = 128,
            [HMACAlgorithmType.HMACSHA1] = 160,
            [HMACAlgorithmType.HMACSHA256] = 256,
            [HMACAlgorithmType.HMACSHA384] = 384,
            [HMACAlgorithmType.HMACSHA512] = 512,
        };
    }
}