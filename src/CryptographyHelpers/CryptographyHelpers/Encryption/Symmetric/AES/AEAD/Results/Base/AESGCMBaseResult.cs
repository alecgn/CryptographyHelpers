using CryptographyHelpers.Results;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AESGCMBaseResult : BaseResult
    {
        public byte[] Key { get; set; }
        public byte[] Nonce { get; set; }
        public byte[] Tag { get; set; }
        public byte[] AssociatedData { get; set; }
    }
}