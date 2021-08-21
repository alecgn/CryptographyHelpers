using CryptographyHelpers.Text.Encoding;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace CryptographyHelpers.KeyDerivation
{
    public class PBKDF2HMACSHA256 : PBKDF2Base, IPBKDF2HMACSHA256
    {
        /// <remarks>
        /// Iterations value based on Owasp Password Storage Cheat Sheet - 2021.
        /// </remarks>
        /// <see cref="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2"/>
        public const int Iterations = 310_000;
        public const KeyDerivationPrf PseudoRandomFunction = KeyDerivationPrf.HMACSHA256;
        private const EncodingType DefaultEncodingType = EncodingType.Hexadecimal;

        public PBKDF2HMACSHA256() : base(PseudoRandomFunction, Iterations, salt: null, DefaultEncodingType) { }

        public PBKDF2HMACSHA256(byte[] salt, EncodingType? encodingType = null)
            : base(PseudoRandomFunction, Iterations, salt, encodingType ?? DefaultEncodingType) { }
    }
}