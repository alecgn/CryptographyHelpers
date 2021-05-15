using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace CryptographyHelpers.KeyDerivation
{
    public class PBKDF2HMACSHA256 : PBKDF2Base, IPBKDF2
    {
        /// <summary>
        /// DefaultIterationCount value based on https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        /// </summary>
        public const int DefaultIterationCount = 310000;
        public const KeyDerivationPrf PseudoRandomFunction = KeyDerivationPrf.HMACSHA256;

        public PBKDF2HMACSHA256() : base(PseudoRandomFunction) { }

        public new PBKDF2KeyDerivationResult DeriveKey(
            string password,
            int bytesRequested,
            byte[] salt = null,
            int iterationCount = DefaultIterationCount)
        {
            return base.DeriveKey(password, bytesRequested, salt, iterationCount);
        }
    }
}