using CryptographyHelpers.Hash.Enums;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.HMAC
{
    [ExcludeFromCodeCoverage]
    public class HMACSHA256 : HMACBase
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA256;

        public HMACSHA256() : base(HashAlgorithm) { }
    }
}
