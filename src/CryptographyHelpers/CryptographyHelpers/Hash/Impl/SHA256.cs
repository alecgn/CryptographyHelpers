using System.Security.Authentication;

namespace CryptographyHelpers.Hash
{
    public class SHA256 : HashCore, ISHA256
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Sha256;

        public SHA256() : base(HashAlgorithm) { }
    }
}