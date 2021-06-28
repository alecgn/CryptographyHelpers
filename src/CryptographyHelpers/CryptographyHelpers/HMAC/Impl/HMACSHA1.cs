using System.Security.Authentication;

namespace CryptographyHelpers.HMAC
{
    public class HMACSHA1 : HMACBase, IHMACSHA1
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Sha1;

        public HMACSHA1() : base(HashAlgorithm, key: null) { }
    }
}