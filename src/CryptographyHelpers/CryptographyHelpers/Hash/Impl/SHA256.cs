using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.Hash
{
    [ExcludeFromCodeCoverage]
    public class SHA256 : HashBase, ISHA256
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA256;

        public SHA256() : base(HashAlgorithm) { }
    }
}