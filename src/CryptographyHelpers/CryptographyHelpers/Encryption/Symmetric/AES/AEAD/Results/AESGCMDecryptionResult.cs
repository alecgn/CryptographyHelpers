namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AESGCMDecryptionResult : AESGCMBaseResult
    {
        public byte[] DecryptedData { get; set; }
    }
}