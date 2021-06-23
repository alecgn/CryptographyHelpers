using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public interface IAESGCM : IDisposable
    {
        AESGCMEncryptionResult Encrypt(byte[] data, byte[] associatedData = null);

        AESGCMDecryptionResult Decrypt(byte[] encryptedData, byte[] nonce, byte[] tag, byte[] associatedData = null);
    }
}