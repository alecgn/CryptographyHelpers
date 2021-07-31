using CryptographyHelpers.Text.Encoding;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace CryptographyHelpers.KeyDerivation
{
    public class PBKDF2HMACSHA256 : PBKDF2Base, IPBKDF2HMACSHA256
    {
        /// <summary>
        /// DefaultIterationCount value based on https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        /// </summary>
        public const int Iterations = 310_000;
        public const KeyDerivationPrf PseudoRandomFunction = KeyDerivationPrf.HMACSHA256;
        private const EncodingType DefaultEncodingType = EncodingType.Hexadecimal;

        public PBKDF2HMACSHA256() : base(PseudoRandomFunction, Iterations, salt: null, DefaultEncodingType) { }

        public PBKDF2HMACSHA256(byte[] salt, EncodingType? encodingType = null)
            : base(PseudoRandomFunction, Iterations, salt, encodingType ?? DefaultEncodingType) { }
    }
}