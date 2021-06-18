using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.Resources;
using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public abstract class AESBase
    {
        public event OnMessageHandler OnMessage;
        public event OnProgressHandler OnProgress;

        private const int BytesPerKilobyte = 1024;
        private const int BufferSizeForFileProcessing = 4 * BytesPerKilobyte;

        private readonly byte[] _key;
        private readonly byte[] _IV;
        private readonly CipherMode _cipherMode;
        private readonly PaddingMode _paddingMode;


        public AESBase(byte[] key, byte[] IV, CipherMode cipherMode, PaddingMode paddingMode)
        {
            _key = key;
            _IV = IV;
            _cipherMode = cipherMode;
            _paddingMode = paddingMode;
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

            try
            {
                using var aes = Aes.Create();
                aes.Key = _key ?? aes.Key;
                aes.IV = _IV ?? aes.IV;
                aes.Mode = _cipherMode;
                aes.Padding = _paddingMode;
                using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using var memoryStream = new MemoryStream();
                using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
                cryptoStream.Write(data);

                return new()
                {
                    Success = true,
                    Message = MessageStrings.Encryption_DataEncryptionSuccess,
                    EncryptedData = memoryStream.ToArray(),
                    Key = aes.Key,
                    IV = aes.IV,
                    CipherMode = aes.Mode,
                    PaddingMode = aes.Padding,
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

        internal AESDecryptionResult Decrypt(byte[] encryptedData)
        {
            if (encryptedData is null || encryptedData.Length == 0)
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.Decryption_InputBytesRequired,
                };
            }

            try
            {
                using var aes = Aes.Create();
                aes.Key = _key;
                aes.IV = _IV;
                aes.Mode = _cipherMode;
                aes.Padding = _paddingMode;
                using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using var memoryStream = new MemoryStream();
                using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write);
                cryptoStream.Write(encryptedData);

                return new()
                {
                    Success = true,
                    Message = MessageStrings.Decryption_DataDecryptionSuccess,
                    DecryptedData = memoryStream.ToArray(),
                    Key = aes.Key,
                    IV = aes.IV,
                    CipherMode = aes.Mode,
                    PaddingMode = aes.Padding,
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

        internal AESEncryptionResult EncryptFile(string sourceFilePath, string encryptedFilePath)
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
                    Message = $"{MessageStrings.File_SourceAndDestinationPathsEqual}.",
                };
            }

            var encryptedFilePathDirectory = Path.GetDirectoryName(encryptedFilePath);
            Directory.CreateDirectory(encryptedFilePathDirectory);

            try
            {
                using var aes = Aes.Create();
                aes.Key = _key ?? aes.Key;
                aes.IV = _IV ?? aes.IV;
                aes.Mode = _cipherMode;
                aes.Padding = _paddingMode;
                using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);
                using var sourceFileStream = File.Open(sourceFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                using var encryptedFileStream = File.Open(encryptedFilePath, FileMode.Create, FileAccess.Write, FileShare.None);
                using var cryptoStream = new CryptoStream(encryptedFileStream, encryptor, CryptoStreamMode.Write);
                var buffer = new byte[BufferSizeForFileProcessing];
                int read;
                var percentageDone = 0;

                while ((read = sourceFileStream.Read(buffer, 0, buffer.Length)) > 0)
                {
                    cryptoStream.Write(buffer, 0, read);

                    var tmpPercentageDone = (int)(sourceFileStream.Position * 100 / sourceFileStream.Length);

                    if (tmpPercentageDone != percentageDone)
                    {
                        percentageDone = tmpPercentageDone;

                        OnProgress?.Invoke(percentageDone, percentageDone != 100 ? $"Encrypting ({percentageDone}%)..." : $"Encrypted ({percentageDone}%).");
                    }
                }

                return new()
                {
                    Success = true,
                    Message = MessageStrings.Encryption_FileEncryptionSuccess,
                    Key = aes.Key,
                    IV = aes.IV,
                    CipherMode = aes.Mode,
                    PaddingMode = aes.Padding,
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

        internal AESDecryptionResult DecryptFile(string encryptedFilePath, string decryptedFilePath, LongRangeOptions rangeOptions)
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
                    Message = $"{MessageStrings.File_SourceAndDestinationPathsEqual}.",
                };
            }

            var pathsEqual = decryptedFilePath.Equals(encryptedFilePath, StringComparison.InvariantCultureIgnoreCase);

            try
            {
                using var aes = Aes.Create();
                aes.Key = _key;
                aes.IV = _IV;
                aes.Mode = _cipherMode;
                aes.Padding = _paddingMode;

                using var decryptedFs = File.Open((pathsEqual ? decryptedFilePath + "_tmpdecrypt" : decryptedFilePath), FileMode.Create, FileAccess.Write, FileShare.None);
                using var encryptedFs = File.Open(encryptedFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                encryptedFs.Position = rangeOptions.Start;

                using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
                using var cs = new CryptoStream(decryptedFs, decryptor, CryptoStreamMode.Write);
                var buffer = new byte[BufferSizeForFileProcessing];
                var totalBytesToRead = ((rangeOptions.End == 0 ? encryptedFs.Length : rangeOptions.End) - rangeOptions.Start);
                var totalBytesNotRead = totalBytesToRead;
                long totalBytesRead = 0;
                var percentageDone = 0;

                while (totalBytesNotRead > 0)
                {
                    var bytesRead = encryptedFs.Read(buffer, 0, (int)Math.Min(buffer.Length, totalBytesNotRead));

                    if (bytesRead > 0)
                    {
                        cs.Write(buffer, 0, bytesRead);

                        totalBytesRead += bytesRead;
                        totalBytesNotRead -= bytesRead;
                        var tmpPercentageDone = (int)(totalBytesRead * 100 / totalBytesToRead);

                        if (tmpPercentageDone != percentageDone)
                        {
                            percentageDone = tmpPercentageDone;

                            OnProgress?.Invoke(percentageDone, percentageDone != 100 ? $"Decrypting ({percentageDone}%)..." : $"Decrypted ({percentageDone}%).");
                        }
                    }
                }

                return new()
                {
                    Success = true,
                    Message = MessageStrings.Decryption_FileDecryptionSuccess,
                    Key = aes.Key,
                    IV = aes.IV,
                    CipherMode = aes.Mode,
                    PaddingMode = aes.Padding,
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