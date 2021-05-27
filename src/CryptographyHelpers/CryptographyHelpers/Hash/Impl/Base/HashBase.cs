using CryptographyHelpers.Encoding;
using CryptographyHelpers.Encoding.Enums;
using CryptographyHelpers.Encoding.Options;
using CryptographyHelpers.Extensions;
using CryptographyHelpers.Hash.Enums;
using CryptographyHelpers.Hash.EventHandlers;
using CryptographyHelpers.Hash.Results;
using CryptographyHelpers.Options;
using CryptographyHelpers.Resources;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CryptographyHelpers.Hash
{
    public abstract class HashBase : IHash
    {
        public event OnHashProgressHandler OnHashProgress;
        private const int FileReadBufferSize = 1024 * 4;
        private readonly HashAlgorithmType _hashAlgorithmType;

        public HashBase(HashAlgorithmType hashAlgorithmType) =>
            _hashAlgorithmType = hashAlgorithmType;

        public GenericHashResult ComputeHash(byte[] bytesToComputeHash, SeekOptions seekOptions, EncodingType outputEncodingType = EncodingType.Hexadecimal)
        {
            if (bytesToComputeHash is null || bytesToComputeHash.Length == 0)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputBytesRequired,
                };
            }

            try
            {
                using var hashAlgorithm = (HashAlgorithm)CryptoConfig.CreateFromName(_hashAlgorithmType.ToString());
                var count = seekOptions.Count == 0 ? bytesToComputeHash.Length : seekOptions.Count;
                var hashBytes = hashAlgorithm.ComputeHash(bytesToComputeHash, seekOptions.Offset, count);

                return new GenericHashResult()
                {
                    Success = true,
                    Message = MessageStrings.Hash_ComputeSuccess,
                    HashAlgorithmType = _hashAlgorithmType,
                    OutputEncodingType = outputEncodingType,
                    HashBytes = hashBytes,
                    HashString = outputEncodingType == EncodingType.Hexadecimal 
                        ? Hexadecimal.ToHexadecimalString(hashBytes)
                        : Base64.ToBase64String(hashBytes),
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

        public GenericHashResult ComputeHash(byte[] bytesToComputeHash) =>
            ComputeHash(bytesToComputeHash, new SeekOptions());

        public GenericHashResult ComputeHash(string stringToComputeHash, SeekOptions seekOptions, EncodingType outputEncodingType = EncodingType.Hexadecimal)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputStringRequired,
                };
            }

            var stringToComputeHashBytes = stringToComputeHash.ToUTF8Bytes();

            return ComputeHash(stringToComputeHashBytes, seekOptions, outputEncodingType);
        }

        public GenericHashResult ComputeHash(string stringToComputeHash) =>
            ComputeHash(stringToComputeHash, new SeekOptions());

        public GenericHashResult ComputeFileHash(string fileToComputeHash, LongSeekOptions seekOptions, EncodingType outputEncodingType = EncodingType.Hexadecimal)
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

                    using (var hashAlgorithm = (HashAlgorithm)CryptoConfig.CreateFromName(_hashAlgorithmType.ToString()))
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
                            HashAlgorithmType = _hashAlgorithmType,
                            OutputEncodingType = outputEncodingType,
                            HashBytes = hashAlgorithm.Hash,
                            HashString = outputEncodingType == EncodingType.Hexadecimal
                                ? Hexadecimal.ToHexadecimalString(hashAlgorithm.Hash)
                                : Base64.ToBase64String(hashAlgorithm.Hash),
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

        public GenericHashResult ComputeFileHash(string fileToComputeHash) =>
            ComputeFileHash(fileToComputeHash, new LongSeekOptions());

        public GenericHashResult VerifyHash(byte[] verificationHashBytes, byte[] bytesToVerifyHash)
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
                    Message = MessageStrings.Hash_InputBytesRequired,
                };
            }

            var hashResult = ComputeHash(bytesToVerifyHash);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(verificationHashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }

        public GenericHashResult VerifyHash(string verificationHexadecimalHashString, string stringToVerifyHash)
        {
            if (string.IsNullOrWhiteSpace(verificationHexadecimalHashString))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Strings_InvalidInputString,
                };
            }

            if (!Hexadecimal.IsValidHexadecimalString(verificationHexadecimalHashString))
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

            var hashBytes = Hexadecimal.ToByteArray(verificationHexadecimalHashString);
            var stringToVerifyHashBytes = stringToVerifyHash.ToUTF8Bytes();

            return VerifyHash(stringToVerifyHashBytes, hashBytes);
        }

        public GenericHashResult VerifyFileHash(string verificationHexadecimalHashString, string fileToVerifyHash)
        {
            if (string.IsNullOrWhiteSpace(verificationHexadecimalHashString))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashRequired,
                };
            }

            if (!Hexadecimal.IsValidHexadecimalString(verificationHexadecimalHashString))
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

            var hashBytes = Hexadecimal.ToByteArray(verificationHexadecimalHashString);

            return VerifyFileHash(hashBytes, fileToVerifyHash);
        }

        public GenericHashResult VerifyFileHash(byte[] verificationHashBytes, string fileToVerifyHash)
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

            var hashResult = ComputeFileHash(fileToVerifyHash);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(verificationHashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }

        private void RaiseOnHashProgressEvent(int percentageDone, string message) =>
            OnHashProgress?.Invoke(percentageDone, message);
    }
}