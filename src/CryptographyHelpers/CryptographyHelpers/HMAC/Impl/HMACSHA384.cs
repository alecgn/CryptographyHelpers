using CryptographyHelpers.Text.Encoding;
using System.Security.Authentication;

namespace CryptographyHelpers.HMAC
{
    public class HMACSHA384 : HMACBase, IHMACSHA384
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Sha384;
        private const EncodingType DefaultEncodingType = EncodingType.Hexadecimal;

        public HMACSHA384() : base(HashAlgorithm, key: null, DefaultEncodingType) { }

        public HMACSHA384(byte[] key) : base(HashAlgorithm, key, DefaultEncodingType) { }

        public HMACSHA384(string encodedKey, EncodingType? encodingType = null) : base(HashAlgorithm, encodedKey, encodingType ?? DefaultEncodingType) { }
    }
}