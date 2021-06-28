using System.Security.Authentication;

namespace CryptographyHelpers.HMAC
{
    public class HMACMD5 : HMACBase, IHMACMD5
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Md5;

        public HMACMD5() : base(HashAlgorithm, key: null) { }
    }
}