using CryptographyHelpers.Hash.Enums;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.HMAC
{
    [ExcludeFromCodeCoverage]
    public class HMACMD5 : HMACBase
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.MD5;

        public HMACMD5() : base(HashAlgorithm) { }
    }
}