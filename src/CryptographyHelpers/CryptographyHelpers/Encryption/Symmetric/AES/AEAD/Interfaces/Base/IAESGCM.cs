using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public interface IAESGCM : IDisposable
    {
        AESGCMEncryptionResult Encrypt(byte[] data, OffsetOptions? offsetOptions = null, byte[] associatedData = null);

        AESGCMTextEncryptionResult EncryptText(string plainText, OffsetOptions? offsetOptions = null, string associatedDataText = null);

        AESGCMDecryptionResult Decrypt(byte[] encryptedData, byte[] nonce, byte[] tag, OffsetOptions? offsetOptions = null, byte[] associatedData = null);

        AESGCMTextDecryptionResult DecryptText(string encodedEncryptedText, string encodedNonce, string encodedTag, OffsetOptions? offsetOptions = null, string associatedDataString = null);
    }
}