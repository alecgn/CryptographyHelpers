using CryptographyHelpers.Text.Encoding;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public interface IAESGCM
    {
        //AESGCMEncryptionResult EncryptText(string plainText, EncodingType encryptedTextEncodingType, string associatedData = null);

        AESGCMEncryptionResult Encrypt(byte[] data, byte[] associatedData = null);

        //AESGCMDecryptionResult DecryptText(string encryptedText, string nonce, string tag, EncodingType inputParametersEncodingType, string associatedData = null);

        AESGCMDecryptionResult Decrypt(byte[] encryptedData, byte[] nonce, byte[] tag, byte[] associatedData = null);
    }
}
