using CryptographyHelpers.Results;
using CryptographyHelpers.Text.Encoding;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AESBaseResult : BaseResult
    {
        public EncodingType EncodingType { get; set; }
        public byte[] Key { get; set; }
        public string EncodedKey { get; set; }
        public byte[] IV { get; set; }
        public string EncodedIV { get; set; }
        public CipherMode CipherMode { get; set; }
        public PaddingMode PaddingMode { get; set; }
    }
}