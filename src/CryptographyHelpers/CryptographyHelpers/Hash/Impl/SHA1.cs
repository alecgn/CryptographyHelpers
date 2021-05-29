using CryptographyHelpers.Hash.Enums;

namespace CryptographyHelpers.Hash
{
    public class SHA1 : HashBase
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA1;

        public SHA1() : base(HashAlgorithm) { }
    }
}