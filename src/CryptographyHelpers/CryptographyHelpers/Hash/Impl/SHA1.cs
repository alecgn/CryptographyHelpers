using CryptographyHelpers.Text.Encoding;
using System.Security.Authentication;

namespace CryptographyHelpers.Hash
{
    public class SHA1 : HashBase, ISHA1
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Sha1;

        public SHA1(EncodingType? encodingType = null) : base(HashAlgorithm, encodingType) { }
    }
}