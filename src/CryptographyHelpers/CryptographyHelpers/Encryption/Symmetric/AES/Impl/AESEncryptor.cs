using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AESEncryptor : IPasswordEncryptor
    {
        AESImplementation _aesImplementation;


        public AESEncryptor(AESImplementation aesImplementation)
        {
            _aesImplementation = aesImplementation;
        }


        public string EncryptText(string plainText, string password)
        {
            throw new NotImplementedException();
        }

        public void EncryptFile(string filePath, string password)
        {
            throw new NotImplementedException();
        }

        public void EncryptFile(string filePath, string encryptedFilePath, string password)
        {
            throw new NotImplementedException();
        }
    }
}