using CryptographyHelpers.Options;
using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public interface IAES : IDisposable
    {
        AESEncryptionResult Encrypt(byte[] data);

        AESDecryptionResult Decrypt(byte[] encryptedData);

        AESEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath);

        AESDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath);

        AESDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, LongOffsetOptions offsetOptions);
    }
}