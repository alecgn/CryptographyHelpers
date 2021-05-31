using CryptographyHelpers.Hash.Enums;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.Hash
{
    [ExcludeFromCodeCoverage]
    public class MD5 : HashBase
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.MD5;

        public MD5() : base(HashAlgorithm) { }
    }
}