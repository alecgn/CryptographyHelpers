using CryptographyHelpers.Hash;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.HMAC
{
    [ExcludeFromCodeCoverage]
    public class HMACSHA1 : HMACBase, IHMACSHA1
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA1;

        public HMACSHA1() : base(HashAlgorithm) { }
    }
}
