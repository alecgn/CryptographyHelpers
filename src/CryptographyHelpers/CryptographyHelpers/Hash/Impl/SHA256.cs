using CryptographyHelpers.Hash.Enums;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.Hash
{
    [ExcludeFromCodeCoverage]
    public class SHA256 : HashBase
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA256;

        public SHA256() : base(HashAlgorithm) { }
    }
}