using CryptographyHelpers.Encoding;
using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.Extensions;
using CryptographyHelpers.IoC;
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
        public event OnProgressHandler OnComputeFileHashProgress;
        private const int FileReadBufferSize = 1024 * 4;
        private const EncodingType DefaultEncodingType = EncodingType.Hexadecimal;
        private readonly HashAlgorithmType _hashAlgorithmType;
        private readonly ServiceLocator _serviceLocator = ServiceLocator.Instance;


        public HashBase(HashAlgorithmType hashAlgorithmType) =>
            _hashAlgorithmType = hashAlgorithmType;


        [ExcludeFromCodeCoverage]
        public HashResult ComputeHash(string stringToComputeHash) =>
            ComputeHash(stringToComputeHash, outputEncodingType: DefaultEncodingType, new SeekOptions());

        [ExcludeFromCodeCoverage]
        public HashResult ComputeHash(string stringToComputeHash, EncodingType outputEncodingType) =>
            ComputeHash(stringToComputeHash, outputEncodingType, new SeekOptions());

        public HashResult ComputeHash(string stringToComputeHash, EncodingType outputEncodingType, SeekOptions seekOptions)
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

            return ComputeHash(stringToComputeHashBytes, outputEncodingType, seekOptions);
        }

        [ExcludeFromCodeCoverage]
        public HashResult ComputeHash(byte[] bytesToComputeHash) =>
            ComputeHash(bytesToComputeHash, outputEncodingType: DefaultEncodingType, new SeekOptions());

        [ExcludeFromCodeCoverage]
        public HashResult ComputeHash(byte[] bytesToComputeHash, EncodingType outputEncodingType) =>
            ComputeHash(bytesToComputeHash, outputEncodingType, new SeekOptions());

        public HashResult ComputeHash(byte[] bytesToComputeHash, EncodingType outputEncodingType, SeekOptions seekOptions)
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
                        ? _serviceLocator.GetService<IHexadecimal>().EncodeToString(hashBytes)
                        : _serviceLocator.GetService<IBase64>().EncodeToString(hashBytes),
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
            ComputeFileHash(fileToComputeHash, outputEncodingType: DefaultEncodingType, new LongSeekOptions());

        [ExcludeFromCodeCoverage]
        public HashResult ComputeFileHash(string fileToComputeHash, EncodingType outputEncodingType) =>
            ComputeFileHash(fileToComputeHash, outputEncodingType, new LongSeekOptions());

        public HashResult ComputeFileHash(string fileToComputeHash, EncodingType outputEncodingType, LongSeekOptions seekOptions)
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

                                    OnComputeFileHashProgress?.Invoke(percentageDone, (percentageDone != 100 ? $"Computing hash ({percentageDone}%)..." : $"Hash computed ({percentageDone}%)."));
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
                                ? _serviceLocator.GetService<IHexadecimal>().EncodeToString(hashAlgorithm.Hash)
                                : _serviceLocator.GetService<IBase64>().EncodeToString(hashAlgorithm.Hash),
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
            VerifyHash(stringToVerifyHash, verificationHashString, verificationHashStringEncodingType: DefaultEncodingType, new SeekOptions());

        [ExcludeFromCodeCoverage]
        public HashResult VerifyHash(string stringToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType) =>
            VerifyHash(stringToVerifyHash, verificationHashString, verificationHashStringEncodingType, new SeekOptions());

        public HashResult VerifyHash(string stringToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType, SeekOptions seekOptions)
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

            try
            {
                var verificationHashBytes = verificationHashStringEncodingType == EncodingType.Hexadecimal
                    ? _serviceLocator.GetService<IHexadecimal>().DecodeString(verificationHashString)
                    : _serviceLocator.GetService<IBase64>().DecodeString(verificationHashString);

                //if (verificationHashStringEncodingType == EncodingType.Hexadecimal)
                //{
                //    if (!Hexadecimal.IsValidHexadecimalString(verificationHashString))
                //    {
                //        return new HashResult()
                //        {
                //            Success = false,
                //            Message = MessageStrings.Strings_InvalidInputHexadecimalString,
                //        };
                //    }

                //    verificationHashBytes = Hexadecimal.ToByteArray(verificationHashString);
                //}

                //if (verificationHashStringEncodingType == EncodingType.Base64)
                //{
                //    if (!Base64.IsValidBase64String(verificationHashString))
                //    {
                //        return new HashResult()
                //        {
                //            Success = false,
                //            Message = MessageStrings.Strings_InvalidInputBase64String,
                //        };
                //    }

                //    verificationHashBytes = Base64.ToByteArray(verificationHashString);
                //}

                var stringToVerifyHashBytes = stringToVerifyHash.ToUTF8Bytes();

                return VerifyHash(stringToVerifyHashBytes, verificationHashBytes, seekOptions);
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

            var hashResult = ComputeHash(bytesToVerifyHash, outputEncodingType: DefaultEncodingType, seekOptions);

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
            VerifyFileHash(fileToVerifyHash, verificationHashString, verificationHashStringEncodingType: DefaultEncodingType, new LongSeekOptions());

        [ExcludeFromCodeCoverage]
        public HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType) =>
            VerifyFileHash(fileToVerifyHash, verificationHashString, verificationHashStringEncodingType, new LongSeekOptions());

        public HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType, LongSeekOptions seekOptions)
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
                if (!_serviceLocator.GetService<IHexadecimal>().IsValidEncodedString(verificationHashString))
                {
                    return new HashResult()
                    {
                        Success = false,
                        Message = MessageStrings.Strings_InvalidInputHexadecimalString,
                    };
                }

                verificationHashBytes = _serviceLocator.GetService<IHexadecimal>().DecodeString(verificationHashString);
            }

            if (verificationHashStringEncodingType == EncodingType.Base64)
            {
                if (!_serviceLocator.GetService<IBase64>().IsValidEncodedString(verificationHashString))
                {
                    return new HashResult()
                    {
                        Success = false,
                        Message = MessageStrings.Strings_InvalidInputBase64String,
                    };
                }

                verificationHashBytes = _serviceLocator.GetService<IBase64>().DecodeString(verificationHashString);
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

            var hashResult = ComputeFileHash(fileToVerifyHash, outputEncodingType: DefaultEncodingType, seekOptions);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(verificationHashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }
    }
}