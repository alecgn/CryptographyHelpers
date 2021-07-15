using CryptographyHelpers.Text.Encoding;
using System.Security.Authentication;

namespace CryptographyHelpers.HMAC
{
    public class HMACMD5 : HMACBase, IHMACMD5
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Md5;
        private const EncodingType DefaultEncodingType = EncodingType.Hexadecimal;

        public HMACMD5() : base(HashAlgorithm, key: null, DefaultEncodingType) { }

        public HMACMD5(byte[] key) : base(HashAlgorithm, key, DefaultEncodingType) { }

        public HMACMD5(string encodedKey, EncodingType? encodingType = null) : base(HashAlgorithm, encodedKey, encodingType ?? DefaultEncodingType) { }
    }
}