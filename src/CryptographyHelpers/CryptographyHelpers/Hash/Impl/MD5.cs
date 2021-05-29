using CryptographyHelpers.Hash.Enums;

namespace CryptographyHelpers.Hash
{
    public class MD5 : HashBase
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.MD5;

        public MD5() : base(HashAlgorithm) { }
    }
}