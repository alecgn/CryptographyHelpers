using CryptographyHelpers.Hash.Enums;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.HMAC
{
    [ExcludeFromCodeCoverage]
    public class HMACSHA384 : HMACBase
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA384;

        public HMACSHA384() : base(HashAlgorithm) { }
    }
}
