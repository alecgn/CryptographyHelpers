using CryptographyHelpers.Hash.Enums;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.HMAC
{
    [ExcludeFromCodeCoverage]
    public class HMACSHA1 : HMACBase
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA1;

        public HMACSHA1() : base(HashAlgorithm) { }
    }
}
