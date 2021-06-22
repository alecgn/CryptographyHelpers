using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
//using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using System;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public abstract class AESGGMBase : IAESGCM, IDisposable
    {
        private readonly AesGcm _aesGcm;
        private readonly byte[] _key;
        private readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;


        public AESGGMBase(byte[] key)
        {
            _key = key;
            _aesGcm = new(_key);
        }

        /// <summary>
        /// This constructor call creates a random key with specified size.
        /// </summary>
        /// <param name="keySizeToGenerateRandomKey"></param>
        public AESGGMBase(AESKeySizes keySizeToGenerateRandomKey)
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



        //public AESGCMEncryptionResult EncryptText(string plainText, EncodingType encryptedTextEncodingType, string associatedData = null)
        //{
        //    if (string.IsNullOrWhiteSpace(plainText))
        //    {
        //        return new()
        //        {
        //            Success = false,
        //            Message = MessageStrings.Strings_InvalidInputString,
        //        };
        //    }

        //    var plainTextBytes = plainText.ToUTF8Bytes();
        //    var associatedDataBytes = associatedData?.ToUTF8Bytes();

        //    var encryptionResult = Encrypt(plainTextBytes, associatedDataBytes);

        //    if (encryptionResult.Success)
        //    {
        //        encryptionResult.EncryptedDataString = encryptedTextEncodingType == EncodingType.Base64
        //            ? _serviceLocator.GetService<IBase64>().EncodeToString(encryptionResult.EncryptedData)
        //            : _serviceLocator.GetService<IHexadecimal>().EncodeToString(encryptionResult.EncryptedData);
        //    }

        //    return encryptionResult;
        //}

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

        //public AESGCMDecryptionResult DecryptText(string encryptedText, string nonce, string tag, EncodingType inputParametersEncodingType, string associatedData = null)
        //{
        //    if (string.IsNullOrWhiteSpace(encryptedText))
        //    {
        //        return new()
        //        {
        //            Success = false,
        //            Message = MessageStrings.Strings_InvalidInputString,
        //        };
        //    }

        //    try
        //    {
        //        var encryptedTextBytes = inputParametersEncodingType == EncodingType.Base64
        //            ? _serviceLocator.GetService<IBase64>().DecodeString(encryptedText)
        //            : _serviceLocator.GetService<IHexadecimal>().DecodeString(encryptedText);
        //        var nonceBytes = inputParametersEncodingType == EncodingType.Base64
        //            ? _serviceLocator.GetService<IBase64>().DecodeString(nonce)
        //            : _serviceLocator.GetService<IHexadecimal>().DecodeString(nonce);
        //        var tagBytes = inputParametersEncodingType == EncodingType.Base64
        //            ? _serviceLocator.GetService<IBase64>().DecodeString(tag)
        //            : _serviceLocator.GetService<IHexadecimal>().DecodeString(tag);
        //        var associatedDataBytes = associatedData?.ToUTF8Bytes();

        //        var decryptionResult = Decrypt(encryptedTextBytes, nonceBytes, tagBytes, associatedDataBytes);

        //        if (decryptionResult.Success)
        //        {
        //            decryptionResult.DecryptedDataString = decryptionResult.DecryptedData.ToUTF8String();
        //        }

        //        return decryptionResult;
        //    }
        //    catch (Exception ex)
        //    {
        //        return new()
        //        {
        //            Success = false,
        //            Message = ex.ToString(),
        //        };
        //    }
        //}

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

        public void Dispose() =>
            _aesGcm.Dispose();
    }
}