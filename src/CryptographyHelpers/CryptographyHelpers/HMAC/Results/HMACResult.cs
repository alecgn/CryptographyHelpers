using CryptographyHelpers.Hash;

namespace CryptographyHelpers.HMAC
{
    public class HMACResult : HashResult
    {
        public byte[] Key { get; set; }
    }
}
