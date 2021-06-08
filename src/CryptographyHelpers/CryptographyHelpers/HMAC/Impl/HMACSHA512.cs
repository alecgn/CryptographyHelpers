using CryptographyHelpers.Hash.Enums;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.HMAC
{
    [ExcludeFromCodeCoverage]
    public class HMACSHA512 : HMACBase
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA512;

        public HMACSHA512() : base(HashAlgorithm) { }
    }
}
