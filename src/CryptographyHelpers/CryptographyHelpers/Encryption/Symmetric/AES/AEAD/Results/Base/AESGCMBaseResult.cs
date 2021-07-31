using CryptographyHelpers.Results;
using CryptographyHelpers.Text.Encoding;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AESGCMBaseResult : BaseResult
    {
        public EncodingType EncodingType { get; set; }
        public byte[] Key { get; set; }
        public string EncodedKey { get; set; }
        public byte[] Nonce { get; set; }
        public string EncodedNonce { get; set; }
        public byte[] Tag { get; set; }
        public string EncodedTag { get; set; }
        public byte[] AssociatedData { get; set; }
    }
}