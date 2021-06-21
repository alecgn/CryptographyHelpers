using System.Security.Authentication;

namespace CryptographyHelpers.HMAC
{
    public class HMACSHA512 : HMACBase, IHMACSHA512
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Sha512;

        public HMACSHA512() : base(HashAlgorithm) { }
    }
}