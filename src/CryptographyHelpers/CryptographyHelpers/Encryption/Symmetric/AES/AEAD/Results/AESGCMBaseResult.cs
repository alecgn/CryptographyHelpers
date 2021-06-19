namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AESGCMBaseResult : AESBaseResult
    {
        public byte[] Nonce { get; set; }
        public byte[] Tag { get; set; }
        public byte[] AssociatedData { get; set; }
    }
}