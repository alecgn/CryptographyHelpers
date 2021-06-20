using System.Security.Authentication;

namespace CryptographyHelpers.Hash
{
    public class SHA256 : HashBase, ISHA256
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Sha256;

        public SHA256() : base(HashAlgorithm) { }
    }
}