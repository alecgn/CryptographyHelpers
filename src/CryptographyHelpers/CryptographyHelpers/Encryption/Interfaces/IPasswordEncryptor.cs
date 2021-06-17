namespace CryptographyHelpers.Encryption
{
    public interface IPasswordEncryptor
    {
        string EncryptText(string plainText, string password);

        void EncryptFile(string filePath, string password);

        void EncryptFile(string filePath, string encryptedFilePath, string password);
    }
}