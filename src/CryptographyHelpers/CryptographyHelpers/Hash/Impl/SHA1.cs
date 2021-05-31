using CryptographyHelpers.Hash.Enums;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.Hash
{
    [ExcludeFromCodeCoverage]
    public class SHA1 : HashBase
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA1;

        public SHA1() : base(HashAlgorithm) { }
    }
}