using Microsoft.AspNet.Cryptography.KeyDerivation;

namespace CryptographyHelpers.KeyDerivation
{
    public class PBKDF2HMACSHA512 : PBKDF2Base, IPBKDF2HMACSHA512
    {
        /// <summary>
        /// DefaultIterationCount value based on https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        /// </summary>
        private const int Iterations = 120_000;
        private const KeyDerivationPrf PseudoRandomFunction = KeyDerivationPrf.HMACSHA512;

        public PBKDF2HMACSHA512() : base(PseudoRandomFunction, Iterations) { }
    }
}