using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AESDecryptionResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public byte[] DecryptedDataBytes { get; set; }
        public string DecryptedDataString { get; set; }
        public byte[] Key { get; set; }
        public byte[] IV { get; set; }
        public byte[] Nonce { get; set; }
        public AESCipherMode AesCipherMode { get; set; }
        public PaddingMode PaddingMode { get; set; }
        public byte[] Salt { get; set; }
        public byte[] AuthenticationKey { get; set; }
        public byte[] Tag { get; set; }
    }
}
