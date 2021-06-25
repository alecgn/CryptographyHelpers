using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Options;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using System;
using System.IO;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography;

namespace CryptographyHelpers.Hash
{
    public class HashCore : IHash
    {
        public event OnProgressHandler OnComputeFileHashProgress;
        private const int FileReadBufferSize = 1024 * 4;
        private const EncodingType DefaultEncodingType = EncodingType.Hexadecimal;
        private readonly HashAlgorithmType _hashAlgorithmType;
        private readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;


        public HashCore(HashAlgorithmType hashAlgorithmType) =>
            _hashAlgorithmType = hashAlgorithmType;


        public HashResult ComputeHash(string stringToComputeHash) =>
            ComputeHash(stringToComputeHash, outputEncodingType: DefaultEncodingType, new OffsetOptions());

        public HashResult ComputeHash(string stringToComputeHash, EncodingType outputEncodingType) =>
            ComputeHash(stringToComputeHash, outputEncodingType, new OffsetOptions());

        public HashResult ComputeHash(string stringToComputeHash, EncodingType outputEncodingType, OffsetOptions offsetOptions)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHash))
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputStringRequired,
                };
            }

            var stringToComputeHashBytes = stringToComputeHash.ToUTF8Bytes();

            return ComputeHash(stringToComputeHashBytes, outputEncodingType, offsetOptions);
        }

        public HashResult ComputeHash(byte[] bytesToComputeHash) =>
            ComputeHash(bytesToComputeHash, outputEncodingType: DefaultEncodingType, new OffsetOptions());

        public HashResult ComputeHash(byte[] bytesToComputeHash, EncodingType outputEncodingType) =>
            ComputeHash(bytesToComputeHash, outputEncodingType, new OffsetOptions());

        public HashResult ComputeHash(byte[] bytesToComputeHash, EncodingType outputEncodingType, OffsetOptions offsetOptions)
        {
            if (bytesToComputeHash is null || bytesToComputeHash.Length == 0)
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputBytesRequired,
                };
            }

            try
            {
                using var hashAlgorithm = HashAlgorithm.Create(_hashAlgorithmType.ToString());
                var count = offsetOptions.Count == 0 ? bytesToComputeHash.Length : offsetOptions.Count;
                var hashBytes = hashAlgorithm.ComputeHash(bytesToComputeHash, offsetOptions.Offset, count);

                return new()
                {
                    Success = true,
                    Message = MessageStrings.Hash_ComputeSuccess,
                    HashAlgorithmType = _hashAlgorithmType,
                    HashBytes = hashBytes,
                    HashString = outputEncodingType == EncodingType.Hexadecimal 
                        ? _serviceLocator.GetService<IHexadecimal>().EncodeToString(hashBytes)
                        : _serviceLocator.GetService<IBase64>().EncodeToString(hashBytes),
                    HashStringEncodingType = outputEncodingType,
                };
            }
            catch (Exception ex)
            {
                return new()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }
        }


        public HashResult ComputeFileHash(string fileToComputeHash) =>
            ComputeFileHash(fileToComputeHash, outputEncodingType: DefaultEncodingType, new LongOffsetOptions());

        public HashResult ComputeFileHash(string fileToComputeHash, EncodingType outputEncodingType) =>
            ComputeFileHash(fileToComputeHash, outputEncodingType, new LongOffsetOptions());

        public HashResult ComputeFileHash(string fileToComputeHash, EncodingType outputEncodingType, LongOffsetOptions offsetOptions)
        {
            if (!File.Exists(fileToComputeHash))
            {
                return new()
                {
                    Success = false,
                    Message = $@"{MessageStrings.File_PathNotFound} ""{fileToComputeHash}"".",
                };
            }

            try
            {
                using var fileStream = new FileStream(fileToComputeHash, FileMode.Open, FileAccess.Read, FileShare.None);
                var count = offsetOptions.Count == 0 ? fileStream.Length : offsetOptions.Count;
                fileStream.Position = offsetOptions.Offset;
                var buffer = new byte[FileReadBufferSize];
                var bytesToRead = count - offsetOptions.Offset;
                using var hashAlgorithm = HashAlgorithm.Create(_hashAlgorithmType.ToString());
                var percentageDone = 0;

                while (bytesToRead > 0)
                {
                    var bytesRead = fileStream.Read(buffer, 0, (int)Math.Min(buffer.Length, bytesToRead));

                    if (bytesRead > 0)
                    {
                        bytesToRead -= bytesRead;

                        if (bytesToRead > 0)
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

                return new()
                {
                    Success = true,
                    Message = MessageStrings.Hash_ComputeSuccess,
                    HashAlgorithmType = _hashAlgorithmType,
                    HashBytes = hashAlgorithm.Hash,
                    HashString = outputEncodingType == EncodingType.Hexadecimal
                        ? _serviceLocator.GetService<IHexadecimal>().EncodeToString(hashAlgorithm.Hash)
                        : _serviceLocator.GetService<IBase64>().EncodeToString(hashAlgorithm.Hash),
                    HashStringEncodingType = outputEncodingType,
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


        public HashResult VerifyHash(string stringToVerifyHash, string verificationHashString) =>
            VerifyHash(stringToVerifyHash, verificationHashString, verificationHashStringEncodingType: DefaultEncodingType, new OffsetOptions());

        public HashResult VerifyHash(string stringToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType) =>
            VerifyHash(stringToVerifyHash, verificationHashString, verificationHashStringEncodingType, new OffsetOptions());

        public HashResult VerifyHash(string stringToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType, OffsetOptions offsetOptions)
        {
            if (string.IsNullOrWhiteSpace(stringToVerifyHash))
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.Strings_InvalidInputString,
                };
            }

            if (string.IsNullOrWhiteSpace(verificationHashString))
            {
                return new()
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
                var stringToVerifyHashBytes = stringToVerifyHash.ToUTF8Bytes();

                return VerifyHash(stringToVerifyHashBytes, verificationHashBytes, offsetOptions);
            }
            catch (Exception ex)
            {
                return new()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }
        }

        public HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes) =>
            VerifyHash(bytesToVerifyHash, verificationHashBytes, new OffsetOptions());

        public HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes, OffsetOptions offsetOptions)
        {
            if (verificationHashBytes is null || verificationHashBytes.Length == 0)
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashBytesRequired,
                };
            }

            var hashResult = ComputeHash(bytesToVerifyHash, outputEncodingType: DefaultEncodingType, offsetOptions);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(verificationHashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }


        public HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString) =>
            VerifyFileHash(fileToVerifyHash, verificationHashString, verificationHashStringEncodingType: DefaultEncodingType, new LongOffsetOptions());

        public HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType) =>
            VerifyFileHash(fileToVerifyHash, verificationHashString, verificationHashStringEncodingType, new LongOffsetOptions());

        public HashResult VerifyFileHash(string fileToVerifyHash, string verificationHashString, EncodingType verificationHashStringEncodingType, LongOffsetOptions offsetOptions)
        {
            if (string.IsNullOrWhiteSpace(verificationHashString))
            {
                return new()
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

                return VerifyFileHash(fileToVerifyHash, verificationHashBytes, offsetOptions);
            }
            catch (Exception ex)
            {
                return new()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }
        }

        public HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes) =>
            VerifyFileHash(fileToVerifyHash, verificationHashBytes, new LongOffsetOptions());

        public HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes, LongOffsetOptions offsetOptions)
        {
            if (verificationHashBytes is null || verificationHashBytes.Length == 0)
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashBytesRequired,
                };
            }

            var hashResult = ComputeFileHash(fileToVerifyHash, outputEncodingType: DefaultEncodingType, offsetOptions);

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