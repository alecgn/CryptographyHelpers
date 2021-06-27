namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AESEncryptionResult : AESBaseResult
    {
        public byte[] EncryptedData { get; set; }
        public string EncodedEncryptedData { get; set; }
    }
}