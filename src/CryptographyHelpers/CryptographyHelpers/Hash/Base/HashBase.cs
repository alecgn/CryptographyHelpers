using CryptographyHelpers.Encoding;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Util;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CryptographyHelpers.Hash
{
    public class HashBase : IHashBase
    {
        private const int FileReadBufferSize = 1024 * 4;

        public event OnHashProgressHandler OnHashProgress;

        public GenericHashResult ComputeHash(
            byte[] bytesToComputeHash,
            HashAlgorithmType hashAlgorithmType,
            SeekOptions seekOptions,
            HexadecimalEncodingOptions hexadecimalOutputEncodingOptions)
        {
            if (bytesToComputeHash is null || bytesToComputeHash.Length == 0)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputRequired,
                };
            }

            try
            {
                using var hashAlgorithm = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlgorithmType.ToString());
                var count = seekOptions.Count == 0 ? bytesToComputeHash.Length : seekOptions.Count;
                var hash = hashAlgorithm.ComputeHash(bytesToComputeHash, seekOptions.Offset, count);

                return new GenericHashResult()
                {
                    Success = true,
                    Message = MessageStrings.Hash_ComputeSuccess,
                    HashAlgorithmType = hashAlgorithmType,
                    HashBytes = hash,
                    HashString = ServiceLocator.Instance.GetService<IHexadecimal>().ToHexadecimalString(hash, hexadecimalOutputEncodingOptions),
                };
            }
            catch (Exception ex)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }
        }

        public GenericHashResult ComputeHash(
            byte[] bytesToComputeHash,
            HashAlgorithmType hashAlgorithmType)
        {
            if (bytesToComputeHash is null || bytesToComputeHash.Length == 0)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputRequired,
                };
            }

            return ComputeHash(bytesToComputeHash, hashAlgorithmType, new SeekOptions(), new HexadecimalEncodingOptions());
        }

        public GenericHashResult ComputeHash(
            string stringToComputeHash,
            HashAlgorithmType hashAlgorithmType,
            SeekOptions seekOptions,
            HexadecimalEncodingOptions hexadecimalOutputEncodingOptions)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputRequired,
                };
            }

            var stringToComputeHashBytes = StringUtil.GetUTF8BytesFromString(stringToComputeHash);

            return ComputeHash(stringToComputeHashBytes, hashAlgorithmType, seekOptions, hexadecimalOutputEncodingOptions);
        }

        public GenericHashResult ComputeHash(
            string stringToComputeHash,
            HashAlgorithmType hashAlgorithmType)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputRequired,
                };
            }

            var stringToComputeHashBytes = StringUtil.GetUTF8BytesFromString(stringToComputeHash);

            return ComputeHash(stringToComputeHashBytes, hashAlgorithmType, new SeekOptions(), new HexadecimalEncodingOptions());
        }

        public GenericHashResult ComputeFileHash(
            string fileToComputeHash,
            HashAlgorithmType hashAlgorithmType,
            LongSeekOptions seekOptions,
            HexadecimalEncodingOptions hexadecimalOutputEncodingOptions)
        {
            if (!File.Exists(fileToComputeHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = $"{MessageStrings.File_PathNotFound} \"{fileToComputeHash}\".",
                };
            }

            if (new FileInfo(fileToComputeHash).Length == 0)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.File_EmptyInputFile,
                };
            }

            try
            {
                using (var fileStream = new FileStream(fileToComputeHash, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    var count = seekOptions.Count == 0 ? fileStream.Length : seekOptions.Count;
                    fileStream.Position = seekOptions.Offset;
                    var buffer = new byte[FileReadBufferSize];
                    var amount = count - seekOptions.Offset;

                    using (var hashAlgorithm = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlgorithmType.ToString()))
                    {
                        var percentageDone = 0;

                        while (amount > 0)
                        {
                            var bytesRead = fileStream.Read(buffer, 0, (int)Math.Min(buffer.Length, amount));

                            if (bytesRead > 0)
                            {
                                amount -= bytesRead;

                                if (amount > 0)
                                {
                                    hashAlgorithm.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                                }
                                else
                                {
                                    hashAlgorithm.TransformFinalBlock(buffer, 0, bytesRead);
                                }

                                var tmpPercentageDone = (int)(fileStream.Position * 100 / count);

                                if (tmpPercentageDone != percentageDone)
                                {
                                    percentageDone = tmpPercentageDone;

                                    RaiseOnHashProgressEvent(percentageDone, (percentageDone != 100 ? $"Computing hash ({percentageDone}%)..." : $"Hash computed ({percentageDone}%)."));
                                }
                            }
                        }

                        return new GenericHashResult()
                        {
                            Success = true,
                            Message = MessageStrings.Hash_ComputeSuccess,
                            HashAlgorithmType = hashAlgorithmType,
                            HashString = ServiceLocator.Instance.GetService<IHexadecimal>().ToHexadecimalString(hashAlgorithm.Hash, hexadecimalOutputEncodingOptions),
                            HashBytes = hashAlgorithm.Hash,
                        };
                    }
                }
            }
            catch (Exception ex)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public GenericHashResult ComputeFileHash(
            string fileToComputeHash,
            HashAlgorithmType hashAlgorithmType)
        {
            if (!File.Exists(fileToComputeHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = $"{MessageStrings.File_PathNotFound} \"{fileToComputeHash}\".",
                };
            }

            return ComputeFileHash(fileToComputeHash, hashAlgorithmType, new LongSeekOptions(), new HexadecimalEncodingOptions());
        }

        public GenericHashResult VerifyHash(
        byte[] verificationHashBytes,
        byte[] bytesToVerifyHash,
        HashAlgorithmType hashAlgorithmType)
        {
            if (verificationHashBytes is null || verificationHashBytes.Length == 0)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashRequired,
                };
            }

            if (bytesToVerifyHash is null || bytesToVerifyHash.Length == 0)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputRequired,
                };
            }

            var hashResult = ComputeHash(bytesToVerifyHash, hashAlgorithmType);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(verificationHashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }

        public GenericHashResult VerifyHash(
            string verificationHexadecimalHashString,
            string stringToVerifyHash,
            HashAlgorithmType hashAlgorithmType)
        {
            if (string.IsNullOrWhiteSpace(verificationHexadecimalHashString))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Strings_InvalidInputString,
                };
            }

            if (!ServiceLocator.Instance.GetService<IHexadecimal>().IsValidHexadecimalString(verificationHexadecimalHashString))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Strings_InvalidInputHexadecimalString,
                };
            }

            if (string.IsNullOrWhiteSpace(stringToVerifyHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Strings_InvalidInputString,
                };
            }

            var hashBytes = ServiceLocator.Instance.GetService<IHexadecimal>().ToByteArray(verificationHexadecimalHashString);
            var stringToVerifyHashBytes = StringUtil.GetUTF8BytesFromString(stringToVerifyHash);

            return VerifyHash(stringToVerifyHashBytes, hashBytes, hashAlgorithmType);
        }

        public GenericHashResult VerifyFileHash(
            string verificationHexadecimalHashString,
            string fileToVerifyHash,
            HashAlgorithmType hashAlgorithmType)
        {
            if (string.IsNullOrWhiteSpace(verificationHexadecimalHashString))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashRequired,
                };
            }

            if (!ServiceLocator.Instance.GetService<IHexadecimal>().IsValidHexadecimalString(verificationHexadecimalHashString))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Strings_InvalidInputHexadecimalString,
                };
            }

            if (!File.Exists(fileToVerifyHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = $"{MessageStrings.File_PathNotFound} \"{fileToVerifyHash}\".",
                };
            }

            if (new FileInfo(fileToVerifyHash).Length == 0)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.File_EmptyInputFile,
                };
            }

            var hashBytes = ServiceLocator.Instance.GetService<IHexadecimal>().ToByteArray(verificationHexadecimalHashString);

            return VerifyFileHash(hashBytes, fileToVerifyHash, hashAlgorithmType);
        }

        public GenericHashResult VerifyFileHash(
            byte[] verificationHashBytes,
            string fileToVerifyHash,
            HashAlgorithmType hashAlgorithmType)
        {
            if (verificationHashBytes is null || verificationHashBytes.Length == 0)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashRequired,
                };
            }

            if (!File.Exists(fileToVerifyHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = $"{MessageStrings.File_PathNotFound} \"{fileToVerifyHash}\".",
                };
            }

            if (new FileInfo(fileToVerifyHash).Length == 0)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.File_EmptyInputFile,
                };
            }

            var hashResult = ComputeFileHash(fileToVerifyHash, hashAlgorithmType);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(verificationHashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }

        private void RaiseOnHashProgressEvent(int percentageDone, string message)
        {
            OnHashProgress?.Invoke(percentageDone, message);
        }
    }
}