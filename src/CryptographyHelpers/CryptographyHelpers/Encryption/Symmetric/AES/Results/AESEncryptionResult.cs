using CryptographyHelpers.Encoding;
using CryptographyHelpers.KeyDerivation;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AESEncryptionResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public byte[] EncryptedDataBytes { get; set; }
        public EncodingType EncryptedDataStringEncodingType { get; set; }
        public string EncryptedDataString { get; set; }
        public byte[] Key { get; set; }
        public int KeyBitSize { get; set; }
        public byte[] IV { get; set; }
        public int IVBitSize { get; set; }
        public byte[] Nonce { get; set; }
        public int NonceBitSize { get; set; }
        public AESCipherMode AESCipherMode { get; set; }
        public PaddingMode PaddingMode { get; set; }
        public PseudoRandomFunction KeyDerivationPseudoRandomFunction { get; set; }
        public int KeyDerivationIterationCount { get; set; }
        public byte[] Salt { get; set; }
        public byte[] AuthenticationKey { get; set; }
        public byte[] Tag { get; set; }
    }
}
