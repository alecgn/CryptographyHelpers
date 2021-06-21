using CryptographyHelpers.Results;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AESBaseResult : BaseResult
    {
        public byte[] Key { get; set; }
        public byte[] IV { get; set; }
        public CipherMode CipherMode { get; set; }
        public PaddingMode PaddingMode { get; set; }
    }
}