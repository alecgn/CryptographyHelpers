namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AESGCMTextEncryptionResult : AESGCMEncryptionResult
    {
        public string EncodedEncryptedText { get; set; }
        public string AssociatedDataText { get; set; }
    }
}
