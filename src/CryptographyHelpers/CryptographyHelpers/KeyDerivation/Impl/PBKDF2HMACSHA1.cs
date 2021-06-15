namespace CryptographyHelpers.KeyDerivation
{
    public class PBKDF2HMACSHA1 : PBKDF2Base, IPBKDF2HMACSHA1
    {
        /// <summary>
        /// DefaultIterationCount value based on https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#pbkdf2
        /// </summary>
        private const int DefaultIterationCount = 720_000;
        private const PseudoRandomFunction PRF = PseudoRandomFunction.HMACSHA1;

        public PBKDF2HMACSHA1() : base(PRF, DefaultIterationCount) { }
    }
}