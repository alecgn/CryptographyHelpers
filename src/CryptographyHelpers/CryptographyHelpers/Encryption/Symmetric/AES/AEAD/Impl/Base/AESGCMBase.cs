using CryptographyHelpers.Resources;
using CryptographyHelpers.Utils;
using System;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public abstract class AESGGMBase : IAESGCM
    {
        private readonly byte[] _key;


        public AESGGMBase(byte[] key) =>
            _key = key;

        public AESGGMBase(AESKeySizes keySizeToGenerateRandomKey) =>
            _key = keySizeToGenerateRandomKey switch
            {
                AESKeySizes.KeySize128Bits => CryptographyUtils.GenerateRandom128BitsKey(),
                AESKeySizes.KeySize192Bits => CryptographyUtils.GenerateRandom192BitsKey(),
                AESKeySizes.KeySize256Bits => CryptographyUtils.GenerateRandom256BitsKey(),
                _ => throw new ArgumentException($"Invalid enum value for {nameof(keySizeToGenerateRandomKey)} parameter of type {typeof(AESKeySizes)}.", nameof(keySizeToGenerateRandomKey)),
            };


        public AESGCMEncryptionResult Encrypt(byte[] data, byte[] associatedData = null)
        {
            if (data is null || data.Length == 0)
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.Encryption_InputBytesRequired,
                };
            }

            // Avoid nonce reuse (catastrophic security breach), randomly generate a new one in every method call
            var nonce = CryptographyUtils.GenerateRandomBytes(AesGcm.NonceByteSizes.MaxSize);
            var encryptedData = new byte[data.Length];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];

            try
            {
                using AesGcm aesGcm = new(_key);
                aesGcm.Encrypt(nonce, data, encryptedData, tag, associatedData);

                return new()
                {
                    Success = true,
                    Message = MessageStrings.Encryption_DataEncryptionSuccess,
                    EncryptedData = encryptedData,
                    Key = _key,
                    Nonce = nonce,
                    Tag = tag,
                    AssociatedData = associatedData,
                };
            }
            catch (Exception ex)
            {
                return new()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public AESGCMDecryptionResult Decrypt(byte[] encryptedData, byte[] nonce, byte[] tag, byte[] associatedData = null)
        {
            if (encryptedData == null || encryptedData.Length == 0)
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.Decryption_InputBytesRequired,
                };
            }

            var decryptedData = new byte[encryptedData.Length];

            try
            {
                using AesGcm aesGcm = new(_key);
                aesGcm.Decrypt(nonce, encryptedData, tag, decryptedData, associatedData);

                return new()
                {
                    Success = true,
                    Message = MessageStrings.Decryption_DataDecryptionSuccess,
                    DecryptedData = decryptedData,
                    Key = _key,
                    Nonce = nonce,
                    Tag = tag,
                    AssociatedData = associatedData,
                };

            }
            catch (Exception ex)
            {
                return new()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }
    }
}