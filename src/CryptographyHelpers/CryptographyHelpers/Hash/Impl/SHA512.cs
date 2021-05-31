using CryptographyHelpers.Hash.Enums;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.Hash
{
    [ExcludeFromCodeCoverage]
    public class SHA512 : HashBase
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA512;

        public SHA512() : base(HashAlgorithm) { }
    }
}