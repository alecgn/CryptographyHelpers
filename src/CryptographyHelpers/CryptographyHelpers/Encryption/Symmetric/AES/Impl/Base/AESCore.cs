using CryptographyHelpers.EventHandlers;
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
        private readonly int _bufferSizeInKBForFileProcessing = 4 * Constants.BytesPerKilobyte;
        private readonly EncodingType _encodingType = EncodingType.Hexadecimal;

        private readonly Aes _aes;


        public AESCore(byte[] key, byte[] IV, CipherMode? cipherMode, PaddingMode? paddingMode, EncodingType? encodingType = null, int? bufferSizeInKBForFileProcessing = null)
        {
            _aes = Aes.Create();
            _aes.Key = key;
            _aes.IV = IV;
            _aes.Mode = cipherMode ?? DefaultCipherMode;
            _aes.Padding = paddingMode ?? DefaultPaddingMode;
            _encodingType = encodingType ?? _encodingType;
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


        public AESEncryptionResult Encrypt(byte[] data)
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
                using (var encryptor = _aes.CreateEncryptor(_aes.Key, _aes.IV))
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        using (var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(data);
                        }

                        encryptedData = memoryStream.ToArray();
                    }
                }

                return new()
                {
                    Success = true,
                    Message = MessageStrings.Encryption_DataEncryptionSuccess,
                    EncryptedData = encryptedData,
                    Key = _aes.Key,
                    IV = _aes.IV,
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

        public AESDecryptionResult Decrypt(byte[] encryptedData)
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
                using (var decryptor = _aes.CreateDecryptor(_aes.Key, _aes.IV))
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(encryptedData);
                        }

                        decryptedData = memoryStream.ToArray();
                    }
                }

                return new()
                {
                    Success = true,
                    Message = MessageStrings.Decryption_DataDecryptionSuccess,
                    DecryptedData = decryptedData,
                    Key = _aes.Key,
                    IV = _aes.IV,
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

        public AESFileEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath) =>
            EncryptFile(sourceFilePath, encryptedFilePath, new LongOffsetOptions());

        public AESFileEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath, LongOffsetOptions offsetOptions)
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
                        sourceFileStream.Position = offsetOptions.Offset;

                        using (var encryptedFileStream = File.Open(encryptedFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                        {
                            using (var cryptoStream = new CryptoStream(encryptedFileStream, encryptor, CryptoStreamMode.Write))
                            {
                                var buffer = new byte[_bufferSizeInKBForFileProcessing];
                                var totalBytesToRead = offsetOptions.Count == 0L ? sourceFileStream.Length : offsetOptions.Count;
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
                    Key = _aes.Key,
                    IV = _aes.IV,
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

        public AESFileDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath) =>
            DecryptFile(encryptedFilePath, decryptedFilePath, new LongOffsetOptions());

        public AESFileDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, LongOffsetOptions offsetOptions)
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
                        encryptedFileStream.Position = offsetOptions.Offset;

                        using (var decryptor = _aes.CreateDecryptor(_aes.Key, _aes.IV))
                        {
                            using (var cryptoStream = new CryptoStream(decryptedFileStream, decryptor, CryptoStreamMode.Write))
                            {
                                var buffer = new byte[_bufferSizeInKBForFileProcessing];
                                var totalBytesToRead = offsetOptions.Count == 0L ? encryptedFileStream.Length : offsetOptions.Count;
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
                    Key = _aes.Key,
                    IV = _aes.IV,
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