using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AESDecryptionResult : AESBaseResult
    {
        public byte[] DecryptedData { get; set; }
        public byte[] IV { get; set; }
        public CipherMode CipherMode { get; set; }
        public PaddingMode PaddingMode { get; set; }
    }
}