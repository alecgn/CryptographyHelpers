using CryptographyHelpers.Text.Encoding;
using System.Security.Authentication;

namespace CryptographyHelpers.Hash
{
    public class MD5 : HashBase, IMD5
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Md5;

        public MD5(EncodingType? encodingType = null) : base(HashAlgorithm, encodingType) { }
    }
}