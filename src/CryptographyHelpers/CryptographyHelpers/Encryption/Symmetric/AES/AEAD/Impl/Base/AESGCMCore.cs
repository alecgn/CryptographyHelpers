using CryptographyHelpers.IoC;
using CryptographyHelpers.Options;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using System;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AESGCMCore : IAESGCM
    {
        private readonly AesGcm _aesGcm;
        private readonly byte[] _key;
        private readonly EncodingType _encodingType = EncodingType.Base64;
        private readonly IEncoder _encoder;
        private readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;


        public AESGCMCore(byte[] key, EncodingType? encodingType = null)
        {
            _key = key;
            _aesGcm = new AesGcm(_key);
            _encodingType = encodingType ?? _encodingType;
            //_encoder = _encodingType == EncodingType.Base64
            //    ? _serviceLocator.GetService<IBase64>()
            //    : _serviceLocator.GetService<IHexadecimal>();

            if (_encodingType == EncodingType.Base64)
            {
                _encoder = _serviceLocator.GetService<IBase64>();
            }
            else
            {
                _encoder = _serviceLocator.GetService<IHexadecimal>();
            }
        }

        public AESGCMCore(string encodedKey, EncodingType? encodingType = null)
        {
            _encodingType = encodingType ?? _encodingType;
            //_encoder = _encodingType == EncodingType.Base64
            //    ? _serviceLocator.GetService<IBase64>()
            //    : _serviceLocator.GetService<IHexadecimal>();

            if (_encodingType == EncodingType.Base64)
            {
                _encoder = _serviceLocator.GetService<IBase64>();
            }
            else
            {
                _encoder = _serviceLocator.GetService<IHexadecimal>();
            }

            _key = _encoder.DecodeString(encodedKey);
            _aesGcm = new AesGcm(_key);
        }

        /// <summary>
        /// This constructor call creates a random key with specified size.
        /// </summary>
        /// <param name="keySizeToGenerateRandomKey"></param>
        public AESGCMCore(AESKeySizes keySizeToGenerateRandomKey, EncodingType? encodingType = null)
        {
            _key = keySizeToGenerateRandomKey switch
            {
                AESKeySizes.KeySize128Bits => CryptographyUtils.GenerateRandom128BitsKey(),
                AESKeySizes.KeySize192Bits => CryptographyUtils.GenerateRandom192BitsKey(),
                AESKeySizes.KeySize256Bits => CryptographyUtils.GenerateRandom256BitsKey(),
                _ => throw new ArgumentException($"Invalid enum value for {nameof(keySizeToGenerateRandomKey)} parameter of type {typeof(AESKeySizes)}.", nameof(keySizeToGenerateRandomKey)),
            };
            _aesGcm = new AesGcm(_key);
            _encodingType = encodingType ?? _encodingType;
            //_encoder = _encodingType == EncodingType.Base64
            //    ? _serviceLocator.GetService<IBase64>()
            //    : _serviceLocator.GetService<IHexadecimal>();

            if (_encodingType == EncodingType.Base64)
            {
                _encoder = _serviceLocator.GetService<IBase64>();
            }
            else
            {
                _encoder = _serviceLocator.GetService<IHexadecimal>();
            }
        }


        public AESGCMEncryptionResult Encrypt(byte[] data, OffsetOptions? offsetOptions = null, byte[] associatedData = null)
        {
            if (data is null || data.Length == 0)
            {
                return new AESGCMEncryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Encryption_InputBytesRequired,
                };
            }

            try
            {
                var offset = offsetOptions.HasValue ? offsetOptions.Value.Offset : 0;
                var totalBytesToRead = offsetOptions.HasValue
                    ? offsetOptions.Value.Count == 0 ? data.Length : offsetOptions.Value.Count
                    : data.Length;
                var dataPayload = new byte[totalBytesToRead];
                Array.Copy(data, offset, dataPayload, 0, totalBytesToRead);
                // Avoid nonce reuse (catastrophic security breach), randomly generate a new one in every method call
                var nonce = CryptographyUtils.GenerateRandomBytes(AesGcm.NonceByteSizes.MaxSize);
                var encryptedData = new byte[dataPayload.Length];
                var tag = new byte[AesGcm.TagByteSizes.MaxSize];
                _aesGcm.Encrypt(nonce, dataPayload, encryptedData, tag, associatedData);

                return new AESGCMEncryptionResult()
                {
                    Success = true,
                    Message = MessageStrings.Encryption_DataEncryptionSuccess,
                    EncodingType = _encodingType,
                    EncryptedData = encryptedData,
                    Key = _key,
                    EncodedKey = _encoder.EncodeToString(_key),
                    Nonce = nonce,
                    EncodedNonce = _encoder.EncodeToString(nonce),
                    Tag = tag,
                    EncodedTag = _encoder.EncodeToString(tag),
                    AssociatedData = associatedData,
                };
            }
            catch (Exception ex)
            {
                return new AESGCMEncryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public AESGCMTextEncryptionResult EncryptText(string plainText, OffsetOptions? offsetOptions = null, string associatedDataText = null)
        {
            if (string.IsNullOrWhiteSpace(plainText))
            {
                return new AESGCMTextEncryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Encryption_InputStringRequired,
                };
            }

            try
            {
                var offset = offsetOptions.HasValue ? offsetOptions.Value.Offset : 0;
                var totalCharsToRead = offsetOptions.HasValue
                    ? offsetOptions.Value.Count == 0 ? plainText.Length : offsetOptions.Value.Count
                    : plainText.Length;
                var plainTextPayload = plainText.Substring(offset, totalCharsToRead);
                var plainTextPayloadBytes = plainTextPayload.ToUTF8Bytes();
                var associatedDataTextBytes = string.IsNullOrWhiteSpace(associatedDataText) ? null : associatedDataText.ToUTF8Bytes();
                var encryptionResult = Encrypt(plainTextPayloadBytes, offsetOptions, associatedDataTextBytes);

                if (encryptionResult.Success)
                {
                    return new AESGCMTextEncryptionResult()
                    {
                        Success = encryptionResult.Success,
                        Message = encryptionResult.Message,
                        EncodingType = encryptionResult.EncodingType,
                        EncodedEncryptedText = _encoder.EncodeToString(encryptionResult.EncryptedData),
                        EncryptedData = encryptionResult.EncryptedData,
                        Key = encryptionResult.Key,
                        EncodedKey = encryptionResult.EncodedKey,
                        Nonce = encryptionResult.Nonce,
                        EncodedNonce = encryptionResult.EncodedNonce,
                        Tag = encryptionResult.Tag,
                        EncodedTag = _encoder.EncodeToString(encryptionResult.Tag),
                        AssociatedData = encryptionResult.AssociatedData,
                        AssociatedDataString = encryptionResult.AssociatedData.ToUTF8String(),
                    };
                }
                else
                {
                    return new AESGCMTextEncryptionResult()
                    {
                        Success = encryptionResult.Success,
                        Message = encryptionResult.Message,
                    };
                }
            }
            catch (Exception ex)
            {
                return new AESGCMTextEncryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public AESGCMDecryptionResult Decrypt(byte[] encryptedData, byte[] nonce, byte[] tag, OffsetOptions? offsetOptions = null, byte[] associatedData = null)
        {
            if (encryptedData == null || encryptedData.Length == 0)
            {
                return new AESGCMDecryptionResult()
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
                return new AESGCMDecryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }

            return new AESGCMDecryptionResult()
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

        public AESGCMTextDecryptionResult DecryptText(string encodedEncryptedText, string encodedNonce, string encodedTag, OffsetOptions? offsetOptions = null, string associatedDataText = null)
        {
            try
            {
                var offset = offsetOptions.HasValue ? offsetOptions.Value.Offset : 0;
                var totalCharsToRead = offsetOptions.HasValue
                    ? offsetOptions.Value.Count == 0 ? encodedEncryptedText.Length : offsetOptions.Value.Count
                    : encodedEncryptedText.Length;
                var encodedEncryptedTextPayload = encodedEncryptedText.Substring(offset, totalCharsToRead);
                var encryptedTextPayloadBytes = _encoder.DecodeString(encodedEncryptedTextPayload);
                var associatedDataTextBytes = string.IsNullOrWhiteSpace(associatedDataText) ? null : associatedDataText.ToUTF8Bytes();
                var nonceBytes = _encoder.DecodeString(encodedNonce);
                var tagBytes = _encoder.DecodeString(encodedTag);
                var decryptionResult = Decrypt(encryptedTextPayloadBytes, nonceBytes, tagBytes, offsetOptions, associatedDataTextBytes);

                if (decryptionResult.Success)
                {
                    return new AESGCMTextDecryptionResult()
                    {
                        Success = decryptionResult.Success,
                        Message = decryptionResult.Message,
                        EncodingType = decryptionResult.EncodingType,
                        DecryptedData = decryptionResult.DecryptedData,
                        DecryptedText = decryptionResult.DecryptedData.ToUTF8String(),
                        Key = decryptionResult.Key,
                        EncodedKey = decryptionResult.EncodedKey,
                        Nonce = decryptionResult.Nonce,
                        EncodedNonce = decryptionResult.EncodedNonce,
                        Tag = decryptionResult.Tag,
                        EncodedTag = _encoder.EncodeToString(decryptionResult.Tag),
                        AssociatedData = decryptionResult.AssociatedData,
                        AssociatedDataString = decryptionResult.AssociatedData.ToUTF8String(),
                    };
                }
                else
                {
                    return new AESGCMTextDecryptionResult()
                    {
                        Success = decryptionResult.Success,
                        Message = decryptionResult.Message,
                    };
                }
            }
            catch (Exception ex)
            {
                return new AESGCMTextDecryptionResult()
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