using CryptographyHelpers.Hash.Results;

namespace CryptographyHelpers.HMAC.Results
{
    public class HMACResult : HashResult
    {
        public byte[] Key { get; set; }
    }
}
