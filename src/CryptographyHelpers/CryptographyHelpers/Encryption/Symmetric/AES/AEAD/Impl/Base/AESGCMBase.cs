using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using System;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AESGCMBase : IAESGCM
    {
        private readonly AesGcm _aesGcm;
        private readonly byte[] _key;
        private readonly EncodingType _encodingType = EncodingType.Base64;
        private readonly IEncoder _encoder;
        private readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;

        public EncodingType EncodingType { get => _encodingType; }

        public AESGCMBase(byte[] key, EncodingType? encodingType = null)
        {
            _key = key;
            _aesGcm = new AesGcm(_key);
            _encodingType = encodingType ?? _encodingType;
            _encoder = GetEncoder(_encodingType);
        }

        public AESGCMBase(string encodedKey, EncodingType? encodingType = null)
        {
            _encodingType = encodingType ?? _encodingType;
            _encoder = GetEncoder(_encodingType);
            _key = _encoder.DecodeString(encodedKey);
            _aesGcm = new AesGcm(_key);
        }

        /// <summary>
        /// This constructor creates a random key with specified size.
        /// </summary>
        /// <param name="keySizeToGenerateRandomKey"></param>
        public AESGCMBase(AESKeySizes keySizeToGenerateRandomKey, EncodingType? encodingType = null)
        {
            _key = GenerateRandomKey(keySizeToGenerateRandomKey);
            _aesGcm = new AesGcm(_key);
            _encodingType = encodingType ?? _encodingType;
            _encoder = GetEncoder(_encodingType);
        }


        public AESGCMEncryptionResult Encrypt(byte[] data, OffsetOptions offsetOptions = null, byte[] associatedData = null)
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
                byte[] encryptedData;
                // Avoid nonce reuse (catastrophic security breach), randomly generate a new one in every method call
                var nonce = CryptographyUtils.GenerateRandomBytes(AesGcm.NonceByteSizes.MaxSize);
                var tag = new byte[AesGcm.TagByteSizes.MaxSize];

                if (offsetOptions is null)
                {
                    encryptedData = new byte[data.Length];
                    _aesGcm.Encrypt(nonce, data, encryptedData, tag, associatedData);
                }
                else
                {
                    var totalBytesToRead = offsetOptions.Count == 0 ? data.Length : offsetOptions.Count;
                    var dataPayload = new byte[totalBytesToRead];
                    Array.Copy(data, offsetOptions.Offset, dataPayload, 0, totalBytesToRead);
                    encryptedData = new byte[totalBytesToRead];
                    _aesGcm.Encrypt(nonce, dataPayload, encryptedData, tag, associatedData);
                }

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

        public AESGCMTextEncryptionResult EncryptText(string plainText, OffsetOptions offsetOptions = null, string associatedDataText = null)
        {
            if (string.IsNullOrWhiteSpace(plainText))
            {
                return new AESGCMTextEncryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Encryption_InputTextRequired,
                };
            }

            try
            {
                AESGCMEncryptionResult encryptionResult;
                var associatedDataTextBytes = string.IsNullOrWhiteSpace(associatedDataText) ? null : associatedDataText.ToUTF8Bytes();

                if (offsetOptions is null)
                {
                    var plainTextBytes = plainText.ToUTF8Bytes();
                    encryptionResult = Encrypt(plainTextBytes, offsetOptions: null, associatedDataTextBytes);
                }
                else
                {
                    var totalCharsToRead = offsetOptions.Count == 0 ? plainText.Length : offsetOptions.Count;
                    var plainTextPayload = plainText.Substring(offsetOptions.Offset, totalCharsToRead);
                    var plainTextPayloadBytes = plainTextPayload.ToUTF8Bytes();
                    encryptionResult = Encrypt(plainTextPayloadBytes, offsetOptions: null, associatedDataTextBytes);
                }

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
                        AssociatedDataText = associatedDataText,
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

        public AESGCMDecryptionResult Decrypt(byte[] encryptedData, byte[] nonce, byte[] tag, OffsetOptions offsetOptions = null, byte[] associatedData = null)
        {
            if (encryptedData is null || encryptedData.Length == 0)
            {
                return new AESGCMDecryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Decryption_InputBytesRequired,
                };
            }

            try
            {
                byte[] decryptedData;

                if (offsetOptions is null)
                {
                    decryptedData = new byte[encryptedData.Length];
                    _aesGcm.Decrypt(nonce, encryptedData, tag, decryptedData, associatedData);
                }
                else
                {
                    var totalBytesToRead = offsetOptions.Count == 0 ? encryptedData.Length : offsetOptions.Count;
                    var encryptedDataPayload = new byte[totalBytesToRead];
                    Array.Copy(encryptedData, offsetOptions.Offset, encryptedDataPayload, 0, totalBytesToRead);
                    decryptedData = new byte[totalBytesToRead];
                    _aesGcm.Decrypt(nonce, encryptedDataPayload, tag, decryptedData, associatedData);
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
            catch (Exception ex)
            {
                return new AESGCMDecryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public AESGCMTextDecryptionResult DecryptText(string encodedEncryptedText, string encodedNonce, string encodedTag, OffsetOptions offsetOptions = null, string associatedDataText = null)
        {
            if (string.IsNullOrWhiteSpace(encodedEncryptedText))
            {
                return new AESGCMTextDecryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Decryption_InputTextRequired,
                };
            }

            try
            {
                AESGCMDecryptionResult decryptionResult;
                var nonceBytes = _encoder.DecodeString(encodedNonce);
                var tagBytes = _encoder.DecodeString(encodedTag);
                var associatedDataTextBytes = string.IsNullOrWhiteSpace(associatedDataText) ? null : associatedDataText.ToUTF8Bytes();

                if (offsetOptions is null)
                {
                    var encryptedTextdBytes = _encoder.DecodeString(encodedEncryptedText);
                    decryptionResult = Decrypt(encryptedTextdBytes, nonceBytes, tagBytes, offsetOptions: null, associatedDataTextBytes);
                }
                else
                {
                    var totalCharsToRead = offsetOptions.Count == 0 ? encodedEncryptedText.Length : offsetOptions.Count;
                    var encodedEncryptedTextPayload = encodedEncryptedText.Substring(offsetOptions.Offset, totalCharsToRead);
                    var encryptedTextPayloadBytes = _encoder.DecodeString(encodedEncryptedTextPayload);
                    decryptionResult = Decrypt(encryptedTextPayloadBytes, nonceBytes, tagBytes, null, associatedDataTextBytes);
                }

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
                        AssociatedDataText = associatedDataText,
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
            _aesGcm?.Dispose();

        private IEncoder GetEncoder(EncodingType encodingType) =>
            encodingType switch
            {
                EncodingType.Base64 => _serviceLocator.GetService<IBase64Encoder>(),
                EncodingType.Hexadecimal => _serviceLocator.GetService<IHexadecimalEncoder>(),
                _ => throw new InvalidOperationException($@"Unexpected enum value ""{encodingType}"" of type ""{nameof(EncodingType)}""."),
            };

        private byte[] GenerateRandomKey(AESKeySizes keySizeToGenerateRandomKey) =>
            keySizeToGenerateRandomKey switch
            {
                AESKeySizes.KeySize128Bits => CryptographyUtils.GenerateRandom128BitsKey(),
                AESKeySizes.KeySize192Bits => CryptographyUtils.GenerateRandom192BitsKey(),
                AESKeySizes.KeySize256Bits => CryptographyUtils.GenerateRandom256BitsKey(),
                _ => throw new ArgumentException(
                    $@"Unexpected enum value ""{keySizeToGenerateRandomKey}"" for ""{nameof(keySizeToGenerateRandomKey)}"" parameter of type ""{nameof(AESKeySizes)}"".",
                    nameof(keySizeToGenerateRandomKey)),
            };
    }
}