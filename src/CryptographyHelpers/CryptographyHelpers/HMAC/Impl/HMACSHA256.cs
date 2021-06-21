using System.Security.Authentication;

namespace CryptographyHelpers.HMAC
{
    public class HMACSHA256 : HMACBase, IHMACSHA256
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Sha256;

        public HMACSHA256() : base(HashAlgorithm) { }
    }
}