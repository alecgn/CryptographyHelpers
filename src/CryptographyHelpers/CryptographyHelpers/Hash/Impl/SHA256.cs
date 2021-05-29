using CryptographyHelpers.Hash.Enums;

namespace CryptographyHelpers.Hash
{
    public class SHA256 : HashBase
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA256;

        public SHA256() : base(HashAlgorithm) { }
    }
}