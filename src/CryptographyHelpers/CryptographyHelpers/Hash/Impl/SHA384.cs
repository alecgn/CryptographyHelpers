using System.Security.Authentication;

namespace CryptographyHelpers.Hash
{
    public class SHA384 : HashBase, ISHA384
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Sha384;

        public SHA384() : base(HashAlgorithm) { }
    }
}