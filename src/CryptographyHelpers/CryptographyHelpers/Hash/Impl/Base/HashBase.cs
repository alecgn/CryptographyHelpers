using CryptographyHelpers.Encoding;
using CryptographyHelpers.Encoding.Enums;
using CryptographyHelpers.Extensions;
using CryptographyHelpers.Hash.Enums;
using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.Hash.Results;
using CryptographyHelpers.Options;
using CryptographyHelpers.Resources;
using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CryptographyHelpers.Hash
{
    public abstract class HashBase : IHash
    {
        public event OnProgressHandler OnProgress;
        private const int FileReadBufferSize = 1024 * 4;
        private const EncodingType DefaultEncodingType = EncodingType.Hexadecimal;
        private readonly HashAlgorithmType _hashAlgorithmType;


        public HashBase(HashAlgorithmType hashAlgorithmType) =>
            _hashAlgorithmType = hashAlgorithmType;


        [ExcludeFromCodeCoverage]
        public HashResult ComputeHash(string stringToComputeHash) =>
            ComputeHash(stringToComputeHash, new SeekOptions(), DefaultEncodingType);

        [ExcludeFromCodeCoverage]
        public HashResult ComputeHash(string stringToComputeHash, SeekOptions seekOptions) =>
            ComputeHash(stringToComputeHash, seekOptions, DefaultEncodingType);

        public HashResult ComputeHash(string stringToComputeHash, SeekOptions seekOptions, EncodingType outputEncodingType)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHash))
            {
                return new HashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputStringRequired,
                };
            }

            var stringToComputeHashBytes = stringToComputeHash.ToUTF8Bytes();

            return ComputeHash(stringToComputeHashBytes, seekOptions, outputEncodingType);
        }

        [ExcludeFromCodeCoverage]
        public HashResult ComputeHash(byte[] bytesToComputeHash) =>
            ComputeHash(bytesToComputeHash, new SeekOptions(), DefaultEncodingType);

        [ExcludeFromCodeCoverage]
        public HashResult ComputeHash(byte[] bytesToComputeHash, SeekOptions seekOptions) =>
            ComputeHash(bytesToComputeHash, seekOptions, DefaultEncodingType);

        public HashResult ComputeHash(byte[] bytesToComputeHash, SeekOptions seekOptions, EncodingType outputEncodingType)
        {
            if (bytesToComputeHash is null || bytesToComputeHash.Length == 0)
            {
                return new HashResult()
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

                return new HashResult()
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
                return new HashResult()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }
        }


        [ExcludeFromCodeCoverage]
        public HashResult ComputeFileHash(string fileToComputeHash) =>
            ComputeFileHash(fileToComputeHash, new LongSeekOptions(), DefaultEncodingType);

        [ExcludeFromCodeCoverage]
        public HashResult ComputeFileHash(string fileToComputeHash, LongSeekOptions seekOptions) =>
            ComputeFileHash(fileToComputeHash, seekOptions, DefaultEncodingType);

        public HashResult ComputeFileHash(string fileToComputeHash, LongSeekOptions seekOptions, EncodingType outputEncodingType)
        {
            if (!File.Exists(fileToComputeHash))
            {
                return new HashResult()
                {
                    Success = false,
                    Message = $@"{MessageStrings.File_PathNotFound} ""{fileToComputeHash}"".",
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

                                    RaiseOnProgressEvent(percentageDone, (percentageDone != 100 ? $"Computing hash ({percentageDone}%)..." : $"Hash computed ({percentageDone}%)."));
                                }
                            }
                        }

                        return new HashResult()
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
                return new HashResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }


        [ExcludeFromCodeCoverage]
        public HashResult VerifyHash(string stringToVerifyHash, string verificationHashString) =>
            VerifyHash(stringToVerifyHash, verificationHashString, new SeekOptions(), DefaultEncodingType);

        [ExcludeFromCodeCoverage]
        public HashResult VerifyHash(string stringToVerifyHash, string verificationHashString, SeekOptions seekOptions) =>
            VerifyHash(stringToVerifyHash, verificationHashString, seekOptions, DefaultEncodingType);

        public HashResult VerifyHash(string stringToVerifyHash, string verificationHashString, SeekOptions seekOptions, EncodingType verificationHashStringEncodingType)
        {
            if (string.IsNullOrWhiteSpace(stringToVerifyHash))
            {
                return new HashResult()
                {
                    Success = false,
                    Message = MessageStrings.Strings_InvalidInputString,
                };
            }

            if (string.IsNullOrWhiteSpace(verificationHashString))
            {
                return new HashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashStringRequired,
                };
            }

            byte[] verificationHashBytes = null;

            if (verificationHashStringEncodingType == EncodingType.Hexadecimal)
            {
                if (!Hexadecimal.IsValidHexadecimalString(verificationHashString))
                {
                    return new HashResult()
                    {
                        Success = false,
                        Message = MessageStrings.Strings_InvalidInputHexadecimalString,
                    };
                }

                verificationHashBytes = Hexadecimal.ToByteArray(verificationHashString);
            }

            if (verificationHashStringEncodingType == EncodingType.Base64)
            {
                if (!Base64.IsValidBase64String(verificationHashString))
                {
                    return new HashResult()
                    {
                        Success = false,
                        Message = MessageStrings.Strings_InvalidInputBase64String,
                    };
                }

                verificationHashBytes = Base64.ToByteArray(verificationHashString);
            }

            var stringToVerifyHashBytes = stringToVerifyHash.ToUTF8Bytes();

            return VerifyHash(stringToVerifyHashBytes, verificationHashBytes, seekOptions);
        }

        [ExcludeFromCodeCoverage]
        public HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes) =>
            VerifyHash(bytesToVerifyHash, verificationHashBytes, new SeekOptions());

        public HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes, SeekOptions seekOptions)
        {
            if (verificationHashBytes is null || verificationHashBytes.Length == 0)
            {
                return new HashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashBytesRequired,
                };
            }

            var hashResult = ComputeHash(bytesToVerifyHash, seekOptions);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(verificationHashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }


        [ExcludeFromCodeCoverage]
        public HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString) =>
            VerifyFileHash(fileToVerifyHash, verificationHashString, new LongSeekOptions(), DefaultEncodingType);

        [ExcludeFromCodeCoverage]
        public HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, LongSeekOptions seekOptions) =>
            VerifyFileHash(fileToVerifyHash, verificationHashString, seekOptions, DefaultEncodingType);

        public HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, LongSeekOptions seekOptions, EncodingType verificationHashStringEncodingType)
        {
            if (string.IsNullOrWhiteSpace(verificationHashString))
            {
                return new HashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashStringRequired,
                };
            }

            byte[] verificationHashBytes = null;

            if (verificationHashStringEncodingType == EncodingType.Hexadecimal)
            {
                if (!Hexadecimal.IsValidHexadecimalString(verificationHashString))
                {
                    return new HashResult()
                    {
                        Success = false,
                        Message = MessageStrings.Strings_InvalidInputHexadecimalString,
                    };
                }

                verificationHashBytes = Hexadecimal.ToByteArray(verificationHashString);
            }

            if (verificationHashStringEncodingType == EncodingType.Base64)
            {
                if (!Base64.IsValidBase64String(verificationHashString))
                {
                    return new HashResult()
                    {
                        Success = false,
                        Message = MessageStrings.Strings_InvalidInputBase64String,
                    };
                }

                verificationHashBytes = Base64.ToByteArray(verificationHashString);
            }

            return VerifyFileHash(fileToVerifyHash, verificationHashBytes, seekOptions);
        }

        [ExcludeFromCodeCoverage]
        public HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes) =>
            VerifyFileHash(fileToVerifyHash, verificationHashBytes, new LongSeekOptions());

        public HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes, LongSeekOptions seekOptions)
        {
            if (verificationHashBytes is null || verificationHashBytes.Length == 0)
            {
                return new HashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashBytesRequired,
                };
            }

            var hashResult = ComputeFileHash(fileToVerifyHash, seekOptions);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(verificationHashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }


        [ExcludeFromCodeCoverage]
        private void RaiseOnProgressEvent(int percentageDone, string message) =>
            OnProgress?.Invoke(percentageDone, message);
    }
}