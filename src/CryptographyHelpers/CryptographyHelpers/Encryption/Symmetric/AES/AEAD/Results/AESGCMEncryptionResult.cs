namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AESGCMEncryptionResult : AESGCMBaseResult
    {
        public byte[] EncryptedData { get; set; }
    }
}