using CryptographyHelpers.Hash.Enums;

namespace CryptographyHelpers.Hash
{
    public class SHA512 : HashBase
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA512;

        public SHA512() : base(HashAlgorithm) { }
    }
}