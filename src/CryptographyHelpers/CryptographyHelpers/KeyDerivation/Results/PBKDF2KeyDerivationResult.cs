using CryptographyHelpers.Encoding;
using CryptographyHelpers.Results;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.KeyDerivation
{
    [ExcludeFromCodeCoverage]
    public class PBKDF2KeyDerivationResult : BaseResult
    {
        public EncodingType OutputEncodingType { get; set; }
        public string DerivedKeyString { get; set; }
        public byte[] DerivedKeyBytes { get; set; }
        public byte[] Salt { get; set; }
        public KeyDerivationPrf PseudoRandomFunction { get; set; }
        public int Iterations { get; set; }
    }
}