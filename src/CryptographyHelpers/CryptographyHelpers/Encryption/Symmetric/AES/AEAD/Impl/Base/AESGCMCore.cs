using CryptographyHelpers.Resources;
using CryptographyHelpers.Utils;
using System;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AESGCMCore : IAESGCM
    {
        private readonly AesGcm _aesGcm;
        private readonly byte[] _key;


        public AESGCMCore(byte[] key)
        {
            _key = key;
            _aesGcm = new(_key);
        }

        /// <summary>
        /// This constructor call creates a random key with specified size.
        /// </summary>
        /// <param name="keySizeToGenerateRandomKey"></param>
        public AESGCMCore(AESKeySizes keySizeToGenerateRandomKey)
        {
            _key = keySizeToGenerateRandomKey switch
            {
                AESKeySizes.KeySize128Bits => CryptographyUtils.GenerateRandom128BitsKey(),
                AESKeySizes.KeySize192Bits => CryptographyUtils.GenerateRandom192BitsKey(),
                AESKeySizes.KeySize256Bits => CryptographyUtils.GenerateRandom256BitsKey(),
                _ => throw new ArgumentException($"Invalid enum value for {nameof(keySizeToGenerateRandomKey)} parameter of type {typeof(AESKeySizes)}.", nameof(keySizeToGenerateRandomKey)),
            };
            _aesGcm = new(_key);
        }

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
                _aesGcm.Encrypt(nonce, data, encryptedData, tag, associatedData);
            }
            catch (Exception ex)
            {
                return new()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }

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
                _aesGcm.Decrypt(nonce, encryptedData, tag, decryptedData, associatedData);
            }
            catch (Exception ex)
            {
                return new()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }

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

        public void Dispose() =>
            _aesGcm.Dispose();
    }
}