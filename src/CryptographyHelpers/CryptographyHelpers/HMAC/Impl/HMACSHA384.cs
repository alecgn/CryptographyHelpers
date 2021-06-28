using System.Security.Authentication;

namespace CryptographyHelpers.HMAC
{
    public class HMACSHA384 : HMACBase, IHMACSHA384
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Sha384;

        public HMACSHA384() : base(HashAlgorithm, key: null) { }
    }
}