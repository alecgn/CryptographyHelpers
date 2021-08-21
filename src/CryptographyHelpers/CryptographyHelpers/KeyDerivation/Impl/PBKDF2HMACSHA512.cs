using CryptographyHelpers.Text.Encoding;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace CryptographyHelpers.KeyDerivation
{
    public class PBKDF2HMACSHA512 : PBKDF2Base, IPBKDF2HMACSHA512
    {
        /// <remarks>
        /// Iterations value based on Owasp Password Storage Cheat Sheet - 2021.
        /// </remarks>
        /// <see cref="https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2"/>
        private const int Iterations = 120_000;
        private const KeyDerivationPrf PseudoRandomFunction = KeyDerivationPrf.HMACSHA512;
        private const EncodingType DefaultEncodingType = EncodingType.Hexadecimal;

        public PBKDF2HMACSHA512() : base(PseudoRandomFunction, Iterations, salt: null, DefaultEncodingType) { }

        public PBKDF2HMACSHA512(byte[] salt, EncodingType? encodingType = null)
            : base(PseudoRandomFunction, Iterations, salt, encodingType ?? DefaultEncodingType) { }
    }
}