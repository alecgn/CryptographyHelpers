using CryptographyHelpers.Text.Encoding;
using System.Security.Authentication;

namespace CryptographyHelpers.HMAC
{
    public class HMACSHA256 : HMACBase, IHMACSHA256
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Sha256;
        private const EncodingType DefaultEncodingType = EncodingType.Hexadecimal;

        public HMACSHA256() : base(HashAlgorithm, key: null, DefaultEncodingType) { }

        public HMACSHA256(byte[] key) : base(HashAlgorithm, key, DefaultEncodingType) { }

        public HMACSHA256(string encodedKey, EncodingType? encodingType = null) : base(HashAlgorithm, encodedKey, encodingType ?? DefaultEncodingType) { }
    }
}