using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AESEncryptionResult : AESBaseResult
    {
        public byte[] EncryptedData { get; set; }
        public byte[] IV { get; set; }
        public CipherMode CipherMode { get; set; }
        public PaddingMode PaddingMode { get; set; }
    }
}