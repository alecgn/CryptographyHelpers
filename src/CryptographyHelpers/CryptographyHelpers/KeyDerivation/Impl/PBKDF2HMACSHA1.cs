using CryptographyHelpers.HMAC.Enums;
using CryptographyHelpers.KeyDerivation.Results;

namespace CryptographyHelpers.KeyDerivation
{
    public class PBKDF2HMACSHA1 : PBKDF2Base
    {
        /// <summary>
        /// DefaultIterationCount value based on https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        /// </summary>
        private const int DefaultIterationCount = 720000;
        private const HMACAlgorithmType PseudoRandomFunction = HMACAlgorithmType.HMACSHA1;

        public PBKDF2HMACSHA1() : base(PseudoRandomFunction) { }

        public new PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested, byte[] salt = null, int iterationCount = DefaultIterationCount)
        {
            return base.DeriveKey(password, bytesRequested, salt, iterationCount);
        }
    }
}