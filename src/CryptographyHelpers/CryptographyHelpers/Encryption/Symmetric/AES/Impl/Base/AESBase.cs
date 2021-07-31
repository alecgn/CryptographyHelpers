using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AESBase : IAES
    {
        public event OnProgressHandler OnEncryptFileProgress;
        public event OnProgressHandler OnDecryptFileProgress;

        private readonly Aes _aes;
        private readonly CipherMode _cipherMode = CipherMode.CBC;
        private readonly PaddingMode _paddingMode = PaddingMode.PKCS7;
        private readonly EncodingType _encodingType = EncodingType.Base64;
        private readonly IEncoder _encoder;
        private readonly int _bufferSizeInKBForFileProcessing = 4 * Constants.BytesPerKilobyte;
        private readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;


        public AESBase(byte[] key, byte[] IV, CipherMode? cipherMode = null, PaddingMode? paddingMode = null, EncodingType? encodingType = null, int? bufferSizeInKBForFileProcessing = null)
        {
            _aes = Aes.Create();
            _aes.Key = key;
            _aes.IV = IV;
            _aes.Mode = _cipherMode = cipherMode ?? _cipherMode;
            _aes.Padding = _paddingMode = paddingMode ?? _paddingMode;
            _encodingType = encodingType ?? _encodingType;
            //_encoder = _encodingType == EncodingType.Base64
            //    ? _serviceLocator.GetService<IBase64>()
            //    : _serviceLocator.GetService<IHexadecimal>();
            _encoder = _encodingType switch
            {
                EncodingType.Base64 => _serviceLocator.GetService<IBase64Encoder>(),
                EncodingType.Hexadecimal => _serviceLocator.GetService<IHexadecimalEncoder>(),
                _ => throw new InvalidOperationException($@"Unexpected enum value ""{_encodingType}"" of type {typeof(EncodingType)}."),
            };
            _bufferSizeInKBForFileProcessing = bufferSizeInKBForFileProcessing ?? _bufferSizeInKBForFileProcessing;
        }

        public AESBase(string encodedKey, string encodedIV, CipherMode? cipherMode = null, PaddingMode? paddingMode = null, EncodingType? encodingType = null, int? bufferSizeInKBForFileProcessing = null)
        {
            _encodingType = encodingType ?? _encodingType;
            //_encoder = _encodingType == EncodingType.Base64
            //    ? _serviceLocator.GetService<IBase64>()
            //    : _serviceLocator.GetService<IHexadecimal>();
            _encoder = _encodingType switch
            {
                EncodingType.Base64 => _serviceLocator.GetService<IBase64Encoder>(),
                EncodingType.Hexadecimal => _serviceLocator.GetService<IHexadecimalEncoder>(),
                _ => throw new InvalidOperationException($@"Unexpected enum value ""{_encodingType}"" of type {typeof(EncodingType)}."),
            };
            _aes = Aes.Create();
            _aes.Key = _encoder.DecodeString(encodedKey);
            _aes.IV = _encoder.DecodeString(encodedIV);
            _aes.Mode = _cipherMode = cipherMode ?? _cipherMode;
            _aes.Padding = _paddingMode = paddingMode ?? _paddingMode;
            _bufferSizeInKBForFileProcessing = bufferSizeInKBForFileProcessing ?? _bufferSizeInKBForFileProcessing;
        }

        /// <summary>
        /// This constructor call creates a random key with specified size, a random IV and defines CipherMode as CBC and PaddingMode as PKCS7.
        /// </summary>
        /// <param name="keySizeToGenerateRandomKey"></param>
        public AESBase(AESKeySizes keySizeToGenerateRandomKey, CipherMode? cipherMode = null, PaddingMode? paddingMode = null, EncodingType? encodingType = null, int? bufferSizeInKBForFileProcessing = null)
        {
            _aes = Aes.Create();
            _aes.Key = keySizeToGenerateRandomKey switch
            {
                AESKeySizes.KeySize128Bits => CryptographyUtils.GenerateRandom128BitsKey(),
                AESKeySizes.KeySize192Bits => CryptographyUtils.GenerateRandom192BitsKey(),
                AESKeySizes.KeySize256Bits => CryptographyUtils.GenerateRandom256BitsKey(),
                _ => throw new ArgumentException($@"Unexpected enum value ""{keySizeToGenerateRandomKey}"" for {nameof(keySizeToGenerateRandomKey)} parameter of type {typeof(AESKeySizes)}.", nameof(keySizeToGenerateRandomKey)),
            };
            _aes.IV = CryptographyUtils.GenerateRandomAESIV();
            _aes.Mode = _cipherMode = cipherMode ?? _cipherMode;
            _aes.Padding = _paddingMode = paddingMode ?? _paddingMode;
            _encodingType = encodingType ?? _encodingType;
            //_encoder = _encodingType == EncodingType.Base64
            //    ? _serviceLocator.GetService<IBase64>()
            //    : _serviceLocator.GetService<IHexadecimal>();
            _encoder = _encodingType switch
            {
                EncodingType.Base64 => _serviceLocator.GetService<IBase64Encoder>(),
                EncodingType.Hexadecimal => _serviceLocator.GetService<IHexadecimalEncoder>(),
                _ => throw new InvalidOperationException($@"Unexpected enum value ""{_encodingType}"" of type {typeof(EncodingType)}."),
            };
            _bufferSizeInKBForFileProcessing = bufferSizeInKBForFileProcessing ?? _bufferSizeInKBForFileProcessing;
        }


        public AESEncryptionResult Encrypt(byte[] data, OffsetOptions offsetOptions = null)
        {
            if (data is null || data.Length == 0)
            {
                return new AESEncryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Encryption_InputBytesRequired,
                };
            }

            try
            {
                var offset = offsetOptions is null ? 0 : offsetOptions.Offset;
                var totalBytesToRead = offsetOptions is null
                    ? data.Length
                    : offsetOptions.Count == 0 ? data.Length : offsetOptions.Count;
                var dataPayload = new byte[totalBytesToRead];
                Array.Copy(data, offset, dataPayload, 0, totalBytesToRead);
                byte[] encryptedData;

                using (var encryptor = _aes.CreateEncryptor(_aes.Key, _aes.IV))
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(dataPayload);
                        }

                        encryptedData = memoryStream.ToArray();
                    }
                }

                return new AESEncryptionResult()
                {
                    Success = true,
                    Message = MessageStrings.Encryption_DataEncryptionSuccess,
                    EncodingType = _encodingType,
                    EncryptedData = encryptedData,
                    Key = _aes.Key,
                    EncodedKey = _encoder.EncodeToString(_aes.Key),
                    IV = _aes.IV,
                    EncodedIV = _encoder.EncodeToString(_aes.IV),
                    CipherMode = _aes.Mode,
                    PaddingMode = _aes.Padding,
                };
            }
            catch (Exception ex)
            {
                return new AESEncryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public AESTextEncryptionResult EncryptText(string plainText, OffsetOptions offsetOptions = null)
        {
            if (string.IsNullOrWhiteSpace(plainText))
            {
                return new AESTextEncryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Encryption_InputTextRequired,
                };
            }

            try
            {
                var offset = offsetOptions is null ? 0 : offsetOptions.Offset;
                var totalCharsToRead = offsetOptions is null
                    ? plainText.Length
                    : offsetOptions.Count == 0 ? plainText.Length : offsetOptions.Count;
                var plainTextPayload = plainText.Substring(offset, totalCharsToRead);
                var plainTextPayloadBytes = plainTextPayload.ToUTF8Bytes();
                var encryptionResult = Encrypt(plainTextPayloadBytes);

                if (encryptionResult.Success)
                {
                    return new AESTextEncryptionResult()
                    {
                        Success = encryptionResult.Success,
                        Message = encryptionResult.Message,
                        EncodingType = encryptionResult.EncodingType,
                        EncodedEncryptedText = _encoder.EncodeToString(encryptionResult.EncryptedData),
                        EncryptedData = encryptionResult.EncryptedData,
                        Key = encryptionResult.Key,
                        EncodedKey = encryptionResult.EncodedKey,
                        IV = encryptionResult.IV,
                        EncodedIV = encryptionResult.EncodedIV,
                        CipherMode = encryptionResult.CipherMode,
                        PaddingMode = encryptionResult.PaddingMode,
                    };
                }
                else
                {
                    return new AESTextEncryptionResult()
                    {
                        Success = encryptionResult.Success,
                        Message = encryptionResult.Message,
                    };
                }
            }
            catch (Exception ex)
            {
                return new AESTextEncryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public AESFileEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath, LongOffsetOptions offsetOptions = null)
        {
            if (!File.Exists(sourceFilePath))
            {
                return new AESFileEncryptionResult()
                {
                    Success = false,
                    Message = $@"{MessageStrings.File_PathNotFound} ""{sourceFilePath}"".",
                };
            }

            if (encryptedFilePath.Equals(sourceFilePath, StringComparison.OrdinalIgnoreCase))
            {
                return new AESFileEncryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.File_SourceAndDestinationPathsEqual,
                };
            }

            try
            {
                var encryptedFilePathDirectory = Path.GetDirectoryName(encryptedFilePath);
                // creates the directory tree, if it does not exists
                Directory.CreateDirectory(encryptedFilePathDirectory);

                using (var encryptor = _aes.CreateEncryptor(_aes.Key, _aes.IV))
                {
                    using (var sourceFileStream = File.Open(sourceFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        var offset = offsetOptions is null ? 0L : offsetOptions.Offset;
                        sourceFileStream.Position = offset;

                        using (var encryptedFileStream = File.Open(encryptedFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                        {
                            using (var cryptoStream = new CryptoStream(encryptedFileStream, encryptor, CryptoStreamMode.Write))
                            {
                                var buffer = new byte[_bufferSizeInKBForFileProcessing];
                                var totalBytesToRead = offsetOptions is null
                                    ? sourceFileStream.Length
                                    : offsetOptions.Count == 0L ? sourceFileStream.Length : offsetOptions.Count;
                                var totalBytesNotRead = totalBytesToRead;
                                var totalBytesRead = 0L;
                                var percentageDone = 0;

                                while (totalBytesNotRead > 0L)
                                {
                                    var bytesRead = sourceFileStream.Read(buffer, 0, (int)Math.Min(buffer.Length, totalBytesNotRead));

                                    if (bytesRead > 0)
                                    {
                                        cryptoStream.Write(buffer, 0, bytesRead);

                                        totalBytesRead += bytesRead;
                                        totalBytesNotRead -= bytesRead;
                                        var tmpPercentageDone = (int)(totalBytesRead * 100 / totalBytesToRead);

                                        if (tmpPercentageDone != percentageDone)
                                        {
                                            percentageDone = tmpPercentageDone;

                                            OnEncryptFileProgress?.Invoke(percentageDone, percentageDone != 100 ? $"Encrypting ({percentageDone}%)..." : $"Encrypted ({percentageDone}%).");
                                        }
                                    }
                                }
                            }
                        }
                    }

                }

                return new AESFileEncryptionResult()
                {
                    Success = true,
                    Message = MessageStrings.Encryption_FileEncryptionSuccess,
                    EncodingType = _encodingType,
                    Key = _aes.Key,
                    EncodedKey = _encoder.EncodeToString(_aes.Key),
                    IV = _aes.IV,
                    EncodedIV = _encoder.EncodeToString(_aes.IV),
                    CipherMode = _aes.Mode,
                    PaddingMode = _aes.Padding,
                };
            }
            catch (Exception ex)
            {
                return new AESFileEncryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public AESDecryptionResult Decrypt(byte[] encryptedData, OffsetOptions offsetOptions = null)
        {
            if (encryptedData is null || encryptedData.Length == 0)
            {
                return new AESDecryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Decryption_InputBytesRequired,
                };
            }

            try
            {
                var offset = offsetOptions is null ? 0 : offsetOptions.Offset;
                var totalBytesToRead = offsetOptions is null
                    ? encryptedData.Length
                    : offsetOptions.Count == 0 ? encryptedData.Length : offsetOptions.Count;
                var payload = new byte[totalBytesToRead];
                Array.Copy(encryptedData, offset, payload, 0, totalBytesToRead);
                byte[] decryptedData;

                using (var decryptor = _aes.CreateDecryptor(_aes.Key, _aes.IV))
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(payload);
                        }

                        decryptedData = memoryStream.ToArray();
                    }
                }

                return new AESDecryptionResult()
                {
                    Success = true,
                    Message = MessageStrings.Decryption_DataDecryptionSuccess,
                    EncodingType = _encodingType,
                    DecryptedData = decryptedData,
                    Key = _aes.Key,
                    EncodedKey = _encoder.EncodeToString(_aes.Key),
                    IV = _aes.IV,
                    EncodedIV = _encoder.EncodeToString(_aes.IV),
                    CipherMode = _aes.Mode,
                    PaddingMode = _aes.Padding,
                };
            }
            catch (Exception ex)
            {
                return new AESDecryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public AESTextDecryptionResult DecryptText(string encodedEncryptedText, OffsetOptions offsetOptions = null)
        {
            if (string.IsNullOrWhiteSpace(encodedEncryptedText))
            {
                return new AESTextDecryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.Decryption_InputTextRequired,
                };
            }

            try
            {
                var offset = offsetOptions is null ? 0 : offsetOptions.Offset;
                var totalCharsToRead = offsetOptions is null
                    ? encodedEncryptedText.Length
                    : offsetOptions.Count == 0 ? encodedEncryptedText.Length : offsetOptions.Count;
                var encodedEncryptedTextPayload = encodedEncryptedText.Substring(offset, totalCharsToRead);
                var encodedEncryptedTextPayloadBytes = _encoder.DecodeString(encodedEncryptedTextPayload);
                var decryptionResult = Decrypt(encodedEncryptedTextPayloadBytes);

                if (decryptionResult.Success)
                {
                    return new AESTextDecryptionResult()
                    {
                        Success = decryptionResult.Success,
                        Message = decryptionResult.Message,
                        EncodingType = decryptionResult.EncodingType,
                        DecryptedData = decryptionResult.DecryptedData,
                        DecryptedText = decryptionResult.DecryptedData.ToUTF8String(),
                        Key = decryptionResult.Key,
                        EncodedKey = decryptionResult.EncodedKey,
                        IV = decryptionResult.IV,
                        EncodedIV = decryptionResult.EncodedIV,
                        CipherMode = decryptionResult.CipherMode,
                        PaddingMode = decryptionResult.PaddingMode,
                    };
                }
                else
                {
                    return new AESTextDecryptionResult()
                    {
                        Success = decryptionResult.Success,
                        Message = decryptionResult.Message,
                    };
                }
            }
            catch (Exception ex)
            {
                return new AESTextDecryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public AESFileDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, LongOffsetOptions offsetOptions = null)
        {
            if (!File.Exists(encryptedFilePath))
            {
                return new AESFileDecryptionResult()
                {
                    Success = false,
                    Message = $@"{MessageStrings.File_PathNotFound} ""{encryptedFilePath}"".",
                };
            }

            if (encryptedFilePath.Equals(decryptedFilePath, StringComparison.OrdinalIgnoreCase))
            {
                return new AESFileDecryptionResult()
                {
                    Success = false,
                    Message = MessageStrings.File_SourceAndDestinationPathsEqual,
                };
            }

            try
            {
                var decryptedFilePathDirectory = Path.GetDirectoryName(decryptedFilePath);
                Directory.CreateDirectory(decryptedFilePathDirectory);

                using (var decryptedFileStream = File.Open(decryptedFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    using (var encryptedFileStream = File.Open(encryptedFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        var offset = offsetOptions is null ? 0L : offsetOptions.Offset;
                        encryptedFileStream.Position = offset;

                        using (var decryptor = _aes.CreateDecryptor(_aes.Key, _aes.IV))
                        {
                            using (var cryptoStream = new CryptoStream(decryptedFileStream, decryptor, CryptoStreamMode.Write))
                            {
                                var buffer = new byte[_bufferSizeInKBForFileProcessing];
                                var totalBytesToRead = offsetOptions is null
                                    ? encryptedFileStream.Length
                                    : offsetOptions.Count == 0L ? encryptedFileStream.Length : offsetOptions.Count;
                                var totalBytesNotRead = totalBytesToRead;
                                long totalBytesRead = 0L;
                                var percentageDone = 0;

                                while (totalBytesNotRead > 0L)
                                {
                                    var bytesRead = encryptedFileStream.Read(buffer, 0, (int)Math.Min(buffer.Length, totalBytesNotRead));

                                    if (bytesRead > 0)
                                    {
                                        cryptoStream.Write(buffer, 0, bytesRead);

                                        totalBytesRead += bytesRead;
                                        totalBytesNotRead -= bytesRead;
                                        var tmpPercentageDone = (int)(totalBytesRead * 100 / totalBytesToRead);

                                        if (tmpPercentageDone != percentageDone)
                                        {
                                            percentageDone = tmpPercentageDone;

                                            OnDecryptFileProgress?.Invoke(percentageDone, percentageDone != 100 ? $"Decrypting ({percentageDone}%)..." : $"Decrypted ({percentageDone}%).");
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                return new AESFileDecryptionResult()
                {
                    Success = true,
                    Message = MessageStrings.Decryption_FileDecryptionSuccess,
                    EncodingType = _encodingType,
                    Key = _aes.Key,
                    EncodedKey = _encoder.EncodeToString(_aes.Key),
                    IV = _aes.IV,
                    EncodedIV = _encoder.EncodeToString(_aes.IV),
                    CipherMode = _aes.Mode,
                    PaddingMode = _aes.Padding,
                };
            }
            catch (Exception ex)
            {
                return new AESFileDecryptionResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public void Dispose() =>
            _aes?.Dispose();
    }
}