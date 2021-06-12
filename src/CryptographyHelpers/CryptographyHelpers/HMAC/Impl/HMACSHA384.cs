using CryptographyHelpers.Hash;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.HMAC
{
    [ExcludeFromCodeCoverage]
    public class HMACSHA384 : HMACBase, IHMACSHA384
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA384;

        public HMACSHA384() : base(HashAlgorithm) { }
    }
}
