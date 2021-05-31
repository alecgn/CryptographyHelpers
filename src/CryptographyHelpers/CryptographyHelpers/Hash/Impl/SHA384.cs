using CryptographyHelpers.Hash.Enums;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.Hash
{
    [ExcludeFromCodeCoverage]
    public class SHA384 : HashBase
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA384;

        public SHA384() : base(HashAlgorithm) { }
    }
}