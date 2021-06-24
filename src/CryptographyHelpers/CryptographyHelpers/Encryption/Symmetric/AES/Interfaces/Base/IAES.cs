using CryptographyHelpers.Options;
using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public interface IAES : IDisposable
    {
        AESEncryptionResult Encrypt(byte[] data);

        AESDecryptionResult Decrypt(byte[] encryptedData);

        AESFileEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath);

        AESFileEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath, LongOffsetOptions offsetOptions);

        AESFileDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath);

        AESFileDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, LongOffsetOptions offsetOptions);
    }
}