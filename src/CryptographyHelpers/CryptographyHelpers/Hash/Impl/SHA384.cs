using CryptographyHelpers.Hash.Enums;

namespace CryptographyHelpers.Hash
{
    public class SHA384 : HashBase
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA384;

        public SHA384() : base(HashAlgorithm) { }
    }
}