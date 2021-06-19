namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public interface IAESGCM
    {
        AESGCMEncryptionResult Encrypt(byte[] data, byte[] associatedData = null);

        AESGCMDecryptionResult Decrypt(byte[] encryptedData, byte[] nonce, byte[] tag, byte[] associatedData = null);
    }
}
