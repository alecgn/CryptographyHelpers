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
        private readonly int _bufferSizeInKBForFileHashing = 4 * Constants.BytesPerKilobyte;
        private readonly HashAlgorithmType _hashAlgorithmType;
        private readonly HashAlgorithm _hashAlgorithm;
        private readonly EncodingType _encodingType = EncodingType.Hexadecimal;
        private readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;


        public HashCore(HashAlgorithmType hashAlgorithmType, EncodingType? encodingType = null, int? bufferSizeInKBForFileHashing = null)
        {
            _hashAlgorithmType = hashAlgorithmType;
            _hashAlgorithm = HashAlgorithm.Create(_hashAlgorithmType.ToString());
            _encodingType = encodingType ?? _encodingType;
            _bufferSizeInKBForFileHashing = bufferSizeInKBForFileHashing ?? _bufferSizeInKBForFileHashing;
        }


        public HashResult ComputeHash(string stringToComputeHash) =>
            ComputeHash(stringToComputeHash, new OffsetOptions());

        public HashResult ComputeHash(string stringToComputeHash, OffsetOptions offsetOptions)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHash))
            {
                return new HashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputTextRequired,
                };
            }

            var stringToComputeHashBytes = stringToComputeHash.ToUTF8Bytes();

            return ComputeHash(stringToComputeHashBytes, offsetOptions);
        }

        public HashResult ComputeHash(byte[] bytesToComputeHash) =>
            ComputeHash(bytesToComputeHash, new OffsetOptions());

        public HashResult ComputeHash(byte[] bytesToComputeHash, OffsetOptions offsetOptions)
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
                var totalBytesToRead = offsetOptions.Count == 0 ? bytesToComputeHash.Length : offsetOptions.Count;
                var hashBytes = _hashAlgorithm.ComputeHash(bytesToComputeHash, offsetOptions.Offset, totalBytesToRead);
                var hashString = _encodingType == EncodingType.Hexadecimal
                    ? _serviceLocator.GetService<IHexadecimal>().EncodeToString(hashBytes)
                    : _serviceLocator.GetService<IBase64>().EncodeToString(hashBytes);

                return new HashResult()
                {
                    Success = true,
                    Message = MessageStrings.Hash_ComputeSuccess,
                    HashAlgorithmType = _hashAlgorithmType,
                    HashBytes = hashBytes,
                    HashString = hashString,
                    HashStringEncodingType = _encodingType,
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

        public HashResult VerifyHash(string stringToVerifyHash, string encodedVerificationHashString) =>
            VerifyHash(stringToVerifyHash, encodedVerificationHashString, new OffsetOptions());

        public HashResult VerifyHash(string textToVerifyHash, string encodedVerificationHashString, OffsetOptions offsetOptions)
        {
            if (string.IsNullOrWhiteSpace(textToVerifyHash))
            {
                return new HashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputTextRequired,
                };
            }

            if (string.IsNullOrWhiteSpace(encodedVerificationHashString))
            {
                return new HashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashStringRequired,
                };
            }

            try
            {
                var verificationHashBytes = _encodingType == EncodingType.Hexadecimal
                    ? _serviceLocator.GetService<IHexadecimal>().DecodeString(encodedVerificationHashString)
                    : _serviceLocator.GetService<IBase64>().DecodeString(encodedVerificationHashString);
                var stringToVerifyHashBytes = textToVerifyHash.ToUTF8Bytes();

                return VerifyHash(stringToVerifyHashBytes, verificationHashBytes, offsetOptions);
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

        public HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes) =>
            VerifyHash(bytesToVerifyHash, verificationHashBytes, new OffsetOptions());

        public HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes, OffsetOptions offsetOptions)
        {
            if (verificationHashBytes is null || verificationHashBytes.Length == 0)
            {
                return new HashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashBytesRequired,
                };
            }

            var hashResult = ComputeHash(bytesToVerifyHash, offsetOptions);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(verificationHashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }

        public HashResult ComputeFileHash(string fileToComputeHash) =>
            ComputeFileHash(fileToComputeHash, new LongOffsetOptions());

        public HashResult ComputeFileHash(string fileToComputeHash, LongOffsetOptions offsetOptions)
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
                    fileStream.Position = offsetOptions.Offset;
                    var buffer = new byte[_bufferSizeInKBForFileHashing];
                    var totalBytesToRead = offsetOptions.Count == 0L ? fileStream.Length : offsetOptions.Count;
                    var totalBytesNotRead = totalBytesToRead;
                    var totalBytesRead = 0L;
                    var percentageDone = 0;

                    while (totalBytesNotRead > 0L)
                    {
                        var bytesRead = fileStream.Read(buffer, 0, (int)Math.Min(buffer.Length, totalBytesNotRead));

                        if (bytesRead > 0L)
                        {
                            if (totalBytesRead > 0L)
                            {
                                _hashAlgorithm.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                            }
                            else
                            {
                                _hashAlgorithm.TransformFinalBlock(buffer, 0, bytesRead);
                            }

                            totalBytesRead += bytesRead;
                            totalBytesNotRead -= bytesRead;

                            var tmpPercentageDone = (int)(fileStream.Position * 100 / totalBytesToRead);

                            if (tmpPercentageDone != percentageDone)
                            {
                                percentageDone = tmpPercentageDone;

                                OnComputeFileHashProgress?.Invoke(percentageDone, (percentageDone != 100 ? $"Computing hash ({percentageDone}%)..." : $"Hash computed ({percentageDone}%)."));
                            }
                        }
                    }
                }

                return new HashResult()
                {
                    Success = true,
                    Message = MessageStrings.Hash_ComputeSuccess,
                    HashAlgorithmType = _hashAlgorithmType,
                    HashBytes = _hashAlgorithm.Hash,
                    HashString = _encodingType == EncodingType.Hexadecimal
                        ? _serviceLocator.GetService<IHexadecimal>().EncodeToString(_hashAlgorithm.Hash)
                        : _serviceLocator.GetService<IBase64>().EncodeToString(_hashAlgorithm.Hash),
                    HashStringEncodingType = _encodingType,
                };
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

        public HashResult VerifyFileHash(string fileToVerifyHash, string encodedVerificationHashString) =>
            VerifyFileHash(fileToVerifyHash, encodedVerificationHashString, new LongOffsetOptions());

        public HashResult VerifyFileHash(string fileToVerifyHash, string encodedVerificationHashString, LongOffsetOptions offsetOptions)
        {
            if (string.IsNullOrWhiteSpace(encodedVerificationHashString))
            {
                return new HashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashStringRequired,
                };
            }

            try
            {
                var verificationHashBytes = _encodingType == EncodingType.Hexadecimal
                        ? _serviceLocator.GetService<IHexadecimal>().DecodeString(encodedVerificationHashString)
                        : _serviceLocator.GetService<IBase64>().DecodeString(encodedVerificationHashString);

                return VerifyFileHash(fileToVerifyHash, verificationHashBytes, offsetOptions);
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

        public HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes) =>
            VerifyFileHash(fileToVerifyHash, verificationHashBytes, new LongOffsetOptions());

        public HashResult VerifyFileHash(string fileToVerifyHash, byte[] verificationHashBytes, LongOffsetOptions offsetOptions)
        {
            if (verificationHashBytes is null || verificationHashBytes.Length == 0)
            {
                return new HashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashBytesRequired,
                };
            }

            var hashResult = ComputeFileHash(fileToVerifyHash, offsetOptions);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(verificationHashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }

        public void Dispose() =>
            _hashAlgorithm.Dispose();
    }
}