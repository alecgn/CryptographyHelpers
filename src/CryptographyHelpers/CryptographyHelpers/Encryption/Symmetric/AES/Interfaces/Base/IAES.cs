using CryptographyHelpers.Options;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public interface IAES
    {
        AESEncryptionResult Encrypt(byte[] data);

        AESDecryptionResult Decrypt(byte[] encryptedData);

        AESEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath);

        AESDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, LongRangeOptions rangeOptions);
    }
}