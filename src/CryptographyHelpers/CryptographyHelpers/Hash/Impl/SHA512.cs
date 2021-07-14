using CryptographyHelpers.Text.Encoding;
using System.Security.Authentication;

namespace CryptographyHelpers.Hash
{
    public class SHA512 : HashBase, ISHA512
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Sha512;

        public SHA512(EncodingType? encodingType = null) : base(HashAlgorithm, encodingType) { }
    }
}