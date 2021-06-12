using CryptographyHelpers.Hash;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.HMAC
{
    [ExcludeFromCodeCoverage]
    public class HMACSHA512 : HMACBase, IHMACSHA512
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA512;

        public HMACSHA512() : base(HashAlgorithm) { }
    }
}
