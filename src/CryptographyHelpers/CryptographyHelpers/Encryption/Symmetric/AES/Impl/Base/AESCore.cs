using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Options;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AESCore : IAES
    {
        public event OnProgressHandler OnEncryptFileProgress;
        public event OnProgressHandler OnDecryptFileProgress;
        private const CipherMode DefaultCipherMode = CipherMode.CBC;
        private const PaddingMode DefaultPaddingMode = PaddingMode.PKCS7;
        private readonly Aes _aes;
        private readonly EncodingType _encodingType = EncodingType.Base64;
        private readonly IEncoder _encoder;
        private readonly int _bufferSizeInKBForFileProcessing = 4 * Constants.BytesPerKilobyte;
        private readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;


        public AESCore(byte[] key, byte[] IV, CipherMode? cipherMode = null, PaddingMode? paddingMode = null, EncodingType? encodingType = null, int? bufferSizeInKBForFileProcessing = null)
        {
            _aes = Aes.Create();
            _aes.Key = key;
            _aes.IV = IV;
            _aes.Mode = cipherMode ?? DefaultCipherMode;
            _aes.Padding = paddingMode ?? DefaultPaddingMode;
            _encodingType = encodingType ?? _encodingType;
            _encoder = _encodingType == EncodingType.Base64
                ? _serviceLocator.GetService<IBase64>()
                : _serviceLocator.GetService<IHexadecimal>();
            _bufferSizeInKBForFileProcessing = bufferSizeInKBForFileProcessing ?? _bufferSizeInKBForFileProcessing;
        }

        public AESCore(string encodedKey, string encodedIV, CipherMode? cipherMode = null, PaddingMode? paddingMode = null, EncodingType? encodingType = null, int? bufferSizeInKBForFileProcessing = null)
        {
            _encodingType = encodingType ?? _encodingType;
            _encoder = _encodingType == EncodingType.Base64
                ? _serviceLocator.GetService<IBase64>()
                : _serviceLocator.GetService<IHexadecimal>();
            _aes = Aes.Create();
            _aes.Key = _encoder.DecodeString(encodedKey);
            _aes.IV = _encoder.DecodeString(encodedIV);
            _aes.Mode = cipherMode ?? DefaultCipherMode;
            _aes.Padding = paddingMode ?? DefaultPaddingMode;
            _bufferSizeInKBForFileProcessing = bufferSizeInKBForFileProcessing ?? _bufferSizeInKBForFileProcessing;
        }

        /// <summary>
        /// This constructor call creates a random key with specified size, a random IV and defines CipherMode as CBC and PaddingMode as PKCS7.
        /// </summary>
        /// <param name="keySizeToGenerateRandomKey"></param>
        public AESCore(AESKeySizes keySizeToGenerateRandomKey, EncodingType? encodingType = null, int? bufferSizeInKBForFileProcessing = null)
        {
            _aes = Aes.Create();
            _aes.Key = keySizeToGenerateRandomKey switch
            {
                AESKeySizes.KeySize128Bits => CryptographyUtils.GenerateRandom128BitsKey(),
                AESKeySizes.KeySize192Bits => CryptographyUtils.GenerateRandom192BitsKey(),
                AESKeySizes.KeySize256Bits => CryptographyUtils.GenerateRandom256BitsKey(),
                _ => throw new ArgumentException($"Invalid enum value for {nameof(keySizeToGenerateRandomKey)} parameter of type {typeof(AESKeySizes)}.", nameof(keySizeToGenerateRandomKey)),
            };
            _aes.IV = CryptographyUtils.GenerateRandomAESIV();
            _aes.Mode = DefaultCipherMode;
            _aes.Padding = DefaultPaddingMode;
            _encodingType = encodingType ?? _encodingType;
            _bufferSizeInKBForFileProcessing = bufferSizeInKBForFileProcessing ?? _bufferSizeInKBForFileProcessing;
        }


        public AESEncryptionResult Encrypt(byte[] data, OffsetOptions? offsetOptions = null)
        {
            if (data is null || data.Length == 0)
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.Encryption_InputBytesRequired,
                };
            }

            byte[] encryptedData;

            try
            {
                var offset = offsetOptions.HasValue ? offsetOptions.Value.Offset : 0;
                var count = offsetOptions.HasValue 
                    ? offsetOptions.Value.Count == 0 ? data.Length : offsetOptions.Value.Count
                    : data.Length;
                var payload = new byte[count];
                Array.Copy(data, offset, payload, 0, count);

                using (var encryptor = _aes.CreateEncryptor(_aes.Key, _aes.IV))
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(payload);
                        }

                        encryptedData = memoryStream.ToArray();
                    }
                }

                return new()
                {
                    Success = true,
                    Message = MessageStrings.Encryption_DataEncryptionSuccess,
                    EncodingType = _encodingType,
                    EncryptedData = encryptedData,
                    EncodedEncryptedData = _encoder.EncodeToString(encryptedData),
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
                return new()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public AESEncryptionResult EncryptText(string plainText, OffsetOptions? offsetOptions = null)
        {
            if (string.IsNullOrWhiteSpace(plainText))
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.Encryption_InputStringRequired,
                };
            }

            var plainTextBytes = plainText.ToUTF8Bytes();

            return Encrypt(plainTextBytes, offsetOptions);
        }

        public AESFileEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath, LongOffsetOptions? offsetOptions = null)
        {
            if (!File.Exists(sourceFilePath))
            {
                return new()
                {
                    Success = false,
                    Message = $@"{MessageStrings.File_PathNotFound} ""{sourceFilePath}"".",
                };
            }

            if (encryptedFilePath.Equals(sourceFilePath, StringComparison.OrdinalIgnoreCase))
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.File_SourceAndDestinationPathsEqual,
                };
            }

            var encryptedFilePathDirectory = Path.GetDirectoryName(encryptedFilePath);

            try
            {
                Directory.CreateDirectory(encryptedFilePathDirectory);

                using (var encryptor = _aes.CreateEncryptor(_aes.Key, _aes.IV))
                {
                    using (var sourceFileStream = File.Open(sourceFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        var offset = offsetOptions.HasValue ? offsetOptions.Value.Offset : 0L;
                        sourceFileStream.Position = offset;

                        using (var encryptedFileStream = File.Open(encryptedFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                        {
                            using (var cryptoStream = new CryptoStream(encryptedFileStream, encryptor, CryptoStreamMode.Write))
                            {
                                var buffer = new byte[_bufferSizeInKBForFileProcessing];
                                var totalBytesToRead = offsetOptions.HasValue
                                    ? offsetOptions.Value.Count == 0L ? sourceFileStream.Length : offsetOptions.Value.Count
                                    : sourceFileStream.Length;
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

                return new()
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
                return new()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public AESDecryptionResult Decrypt(byte[] encryptedData, OffsetOptions? offsetOptions = null)
        {
            if (encryptedData is null || encryptedData.Length == 0)
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.Decryption_InputBytesRequired,
                };
            }

            byte[] decryptedData;

            try
            {
                var offset = offsetOptions.HasValue ? offsetOptions.Value.Offset : 0;
                var count = offsetOptions.HasValue
                    ? offsetOptions.Value.Count == 0 ? encryptedData.Length : offsetOptions.Value.Count
                    : encryptedData.Length;
                var payload = new byte[count];
                Array.Copy(encryptedData, offset, payload, 0, count);

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

                return new()
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
                return new()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public AESDecryptionResult DecryptText(string encodedEncryptedText, OffsetOptions? offsetOptions = null)
        {
            if (string.IsNullOrWhiteSpace(encodedEncryptedText))
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.Decryption_InputStringRequired,
                };
            }

            var encodedEncryptedTextBytes = _encoder.DecodeString(encodedEncryptedText);

            var decryptionResult =  Decrypt(encodedEncryptedTextBytes, offsetOptions);

            if (decryptionResult.Success)
            {
                decryptionResult.DecryptedDataString = decryptionResult.DecryptedData.ToUTF8String();
            }

            return decryptionResult;
        }

        public AESFileDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, LongOffsetOptions? offsetOptions = null)
        {
            if (!File.Exists(encryptedFilePath))
            {
                return new()
                {
                    Success = false,
                    Message = $@"{MessageStrings.File_PathNotFound} ""{encryptedFilePath}"".",
                };
            }

            if (encryptedFilePath.Equals(decryptedFilePath, StringComparison.OrdinalIgnoreCase))
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.File_SourceAndDestinationPathsEqual,
                };
            }

            var decryptedFilePathDirectory = Path.GetDirectoryName(decryptedFilePath);

            try
            {
                Directory.CreateDirectory(decryptedFilePathDirectory);

                using (var decryptedFileStream = File.Open(decryptedFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    using (var encryptedFileStream = File.Open(encryptedFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                    {
                        var offset = offsetOptions.HasValue ? offsetOptions.Value.Offset : 0L;
                        encryptedFileStream.Position = offset;

                        using (var decryptor = _aes.CreateDecryptor(_aes.Key, _aes.IV))
                        {
                            using (var cryptoStream = new CryptoStream(decryptedFileStream, decryptor, CryptoStreamMode.Write))
                            {
                                var buffer = new byte[_bufferSizeInKBForFileProcessing];
                                var totalBytesToRead = offsetOptions.HasValue
                                    ? offsetOptions.Value.Count == 0L ? encryptedFileStream.Length : offsetOptions.Value.Count
                                    : encryptedFileStream.Length;
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

                return new()
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
                return new()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public void Dispose() =>
            _aes.Dispose();
    }
}