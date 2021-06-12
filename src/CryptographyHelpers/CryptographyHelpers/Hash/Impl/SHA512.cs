using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.Hash
{
    [ExcludeFromCodeCoverage]
    public class SHA512 : HashBase, ISHA512
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA512;

        public SHA512() : base(HashAlgorithm) { }
    }
}