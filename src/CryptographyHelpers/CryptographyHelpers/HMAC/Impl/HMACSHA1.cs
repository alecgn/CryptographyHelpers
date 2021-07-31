using CryptographyHelpers.Text.Encoding;
using System.Security.Authentication;

namespace CryptographyHelpers.HMAC
{
    public class HMACSHA1 : HMACBase, IHMACSHA1
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Sha1;
        private const EncodingType DefaultEncodingType = EncodingType.Hexadecimal;

        public HMACSHA1() : base(HashAlgorithm, key: null, DefaultEncodingType) { }

        public HMACSHA1(byte[] key) : base(HashAlgorithm, key, DefaultEncodingType) { }

        public HMACSHA1(string encodedKey, EncodingType? encodingType = null) : base(HashAlgorithm, encodedKey, encodingType ?? DefaultEncodingType) { }
    }
}