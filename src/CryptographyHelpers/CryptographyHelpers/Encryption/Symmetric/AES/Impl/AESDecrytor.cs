using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AESDecryptor : IPasswordDecryptor
    {
        AESImplementation _aesImplementation;


        public AESDecryptor(AESImplementation aesImplementation)
        {
            _aesImplementation = aesImplementation;
        }


        public string DecryptText(string encryptedText, string password)
        {
            throw new NotImplementedException();
        }

        public void DecryptFile(string encryptedFilePath, string password)
        {
            throw new NotImplementedException();
        }

        public void DecryptFile(string encryptedFilePath, string decryptedFilePath, string password)
        {
            throw new NotImplementedException();
        }
    }
}