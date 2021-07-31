using CryptographyHelpers.Text.Encoding;
using System.Security.Authentication;

namespace CryptographyHelpers.HMAC
{
    public class HMACSHA512 : HMACBase, IHMACSHA512
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Sha512;
        private const EncodingType DefaultEncodingType = EncodingType.Hexadecimal;

        public HMACSHA512() : base(HashAlgorithm, key: null, DefaultEncodingType) { }

        public HMACSHA512(byte[] key) : base(HashAlgorithm, key, DefaultEncodingType) { }

        public HMACSHA512(string encodedKey, EncodingType? encodingType = null) : base(HashAlgorithm, encodedKey, encodingType ?? DefaultEncodingType) { }
    }
}