namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AESGCMTextDecryptionResult : AESGCMDecryptionResult
    {
        public string DecryptedText { get; set; }
        public string AssociatedDataText { get; set; }
    }
}
