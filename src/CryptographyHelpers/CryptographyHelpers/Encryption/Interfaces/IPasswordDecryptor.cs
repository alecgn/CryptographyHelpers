namespace CryptographyHelpers.Encryption
{
    public interface IPasswordDecryptor
    {
        string DecryptText(string encryptedText, string password);

        void DecryptFile(string encryptedFilePath, string password);

        void DecryptFile(string encryptedFilePath, string decryptedFilePath, string password);
    }
}