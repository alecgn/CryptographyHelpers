using Microsoft.AspNet.Cryptography.KeyDerivation;

namespace CryptographyHelpers.KeyDerivation
{
    public class PBKDF2HMACSHA1 : PBKDF2Base, IPBKDF2HMACSHA1
    {
        /// <summary>
        /// DefaultIterationCount value based on https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        /// </summary>
        private const int Iterations = 720_000;
        private const KeyDerivationPrf PseudoRandomFunction = KeyDerivationPrf.HMACSHA1;

        public PBKDF2HMACSHA1() : base(PseudoRandomFunction, Iterations) { }
    }
}