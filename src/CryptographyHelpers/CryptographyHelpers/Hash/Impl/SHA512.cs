using System.Security.Authentication;

namespace CryptographyHelpers.Hash
{
    public class SHA512 : HashCore, ISHA512
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Sha512;

        public SHA512() : base(HashAlgorithm) { }
    }
}