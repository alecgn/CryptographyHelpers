using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.Options;
using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public interface IAES : IDisposable
    {
        public event OnProgressHandler OnEncryptFileProgress;
        public event OnProgressHandler OnDecryptFileProgress;


        AESEncryptionResult Encrypt(byte[] data, OffsetOptions? offsetOptions = null);

        AESFileEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath, LongOffsetOptions? offsetOptions = null);

        AESDecryptionResult Decrypt(byte[] encryptedData, OffsetOptions? offsetOptions = null);

        AESFileDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, LongOffsetOptions? offsetOptions = null);
    }
}