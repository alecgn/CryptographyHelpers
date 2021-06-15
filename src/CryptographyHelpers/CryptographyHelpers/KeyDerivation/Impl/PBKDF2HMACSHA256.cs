namespace CryptographyHelpers.KeyDerivation
{
    public class PBKDF2HMACSHA256 : PBKDF2Base, IPBKDF2HMACSHA256
    {
        /// <summary>
        /// DefaultIterationCount value based on https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        /// </summary>
        public const int DefaultIterationCount = 310_000;
        public const PseudoRandomFunction PRF = PseudoRandomFunction.HMACSHA256;

        public PBKDF2HMACSHA256() : base(PRF, DefaultIterationCount) { }
    }
}