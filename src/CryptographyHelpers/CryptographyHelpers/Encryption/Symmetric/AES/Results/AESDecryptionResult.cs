namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AESDecryptionResult : AESBaseResult
    {
        public byte[] DecryptedData { get; set; }
        public string DecryptedDataString { get; set; }
    }
}