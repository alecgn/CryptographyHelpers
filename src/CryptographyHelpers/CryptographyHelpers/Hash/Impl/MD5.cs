using System.Security.Authentication;

namespace CryptographyHelpers.Hash
{
    public class MD5 : HashCore, IMD5
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Md5;

        public MD5() : base(HashAlgorithm) { }
    }
}