using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace CryptographyHelpers.KeyDerivation
{
    public class PBKDF2KeyDerivationResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string DerivedKeyBase64String { get; set; }
        public byte[] DerivedKeyBytes { get; set; }
        public byte[] Salt { get; set; }
        public KeyDerivationPrf PseudoRandomFunction { get; set; }
        public int IterationCount { get; set; }
    }
}