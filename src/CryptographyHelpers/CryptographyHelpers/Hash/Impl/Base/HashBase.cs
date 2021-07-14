using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using System;
using System.IO;
using System.Linq;
using System.Security.Authentication;
using System.Security.Cryptography;

namespace CryptographyHelpers.Hash
{
    public class HashBase : IHash
    {
        public event OnProgressHandler OnComputeFileHashProgress;

        private readonly HashAlgorithm _hashAlgorithm;
        private readonly HashAlgorithmType _hashAlgorithmType;
        private readonly EncodingType _encodingType = EncodingType.Hexadecimal;
        private readonly IEncoder _encoder;
        private readonly int _bufferSizeInKBForFileHashing = 4 * Constants.BytesPerKilobyte;
        private readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;


        public HashBase(HashAlgorithmType hashAlgorithmType, EncodingType? encodingType = null, int? bufferSizeInKBForFileHashing = null)
        {
            _hashAlgorithmType = hashAlgorithmType;
            _hashAlgorithm = HashAlgorithm.Create(_hashAlgorithmType.ToString());
            _encodingType = encodingType ?? _encodingType;
            _encoder = _encodingType switch
            {
                EncodingType.Hexadecimal => _serviceLocator.GetService<IHexadecimal>(),
                EncodingType.Base64 => _serviceLocator.GetService<IBase64>(),
                _ => throw new InvalidOperationException($@"Unexpected enum value ""{_encodingType}"" of type {typeof(EncodingType)}."),
            };
            _bufferSizeInKBForFileHashing = bufferSizeInKBForFileHashing ?? _bufferSizeInKBForFileHashing;
        }


        public HashResult ComputeHash(byte[] bytesToComputeHash, OffsetOptions? offsetOptions = null)
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
                var offset = offsetOptions.HasValue ? offsetOptions.Value.Offset : 0;
                var totalBytesToRead = offsetOptions.HasValue
                    ? offsetOptions.Value.Count == 0 ? bytesToComputeHash.Length : offsetOptions.Value.Count
                    : bytesToComputeHash.Length;
                var hashBytes = _hashAlgorithm.ComputeHash(bytesToComputeHash, offset, totalBytesToRead);

                return new HashResult()
                {
                    Success = true,
                    Message = MessageStrings.Hash_ComputeSuccess,
                    HashAlgorithmType = _hashAlgorithmType,
                    HashBytes = hashBytes,
                    HashStringEncodingType = _encodingType,
                    HashString = _encoder.EncodeToString(hashBytes),
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

        public HashResult ComputeTextHash(string textToComputeHash, OffsetOptions? offsetOptions = null)
        {
            if (string.IsNullOrWhiteSpace(textToComputeHash))
            {
                return new HashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputTextRequired,
                };
            }

            try
            {
                var offset = offsetOptions.HasValue ? offsetOptions.Value.Offset : 0;
                var totalCharsToRead = offsetOptions.HasValue
                    ? offsetOptions.Value.Count == 0 ? textToComputeHash.Length : offsetOptions.Value.Count
                    : textToComputeHash.Length;
                var textToComputeHashPayload = textToComputeHash.Substring(offset, totalCharsToRead);
                var textToComputeHashPayloadBytes = textToComputeHashPayload.ToUTF8Bytes();

                return ComputeHash(textToComputeHashPayloadBytes);
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

        public HashResult ComputeFileHash(string filePathToComputeHash, LongOffsetOptions? offsetOptions = null)
        {
            if (!File.Exists(filePathToComputeHash))
            {
                return new HashResult()
                {
                    Success = false,
                    Message = $@"{MessageStrings.File_PathNotFound} ""{filePathToComputeHash}"".",
                };
            }

            try
            {
                using (var fileStream = new FileStream(filePathToComputeHash, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    var offset = offsetOptions.HasValue ? offsetOptions.Value.Offset : 0L;
                    var totalBytesToRead = offsetOptions.HasValue
                        ? offsetOptions.Value.Count == 0L ? fileStream.Length : offsetOptions.Value.Count
                        : fileStream.Length;
                    fileStream.Position = offset;
                    var buffer = new byte[_bufferSizeInKBForFileHashing];
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
                    HashStringEncodingType = _encodingType,
                    HashString = _encoder.EncodeToString(_hashAlgorithm.Hash),
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

        public HashResult VerifyHash(byte[] bytesToVerifyHash, byte[] verificationHashBytes, OffsetOptions? offsetOptions = null)
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

        public HashResult VerifyTextHash(string textToVerifyHash, string encodedVerificationHashString, OffsetOptions? offsetOptions = null)
        {
            if (string.IsNullOrWhiteSpace(textToVerifyHash))
            {
                return new HashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputTextRequired,
                };
            }

            try
            {
                var offset = offsetOptions.HasValue ? offsetOptions.Value.Offset : 0;
                var totalCharsToRead = offsetOptions.HasValue
                    ? offsetOptions.Value.Count == 0 ? textToVerifyHash.Length : offsetOptions.Value.Count
                    : textToVerifyHash.Length;
                var textToVerifyHashPayload = textToVerifyHash.Substring(offset, totalCharsToRead);
                var verificationHashBytes = _encoder.DecodeString(encodedVerificationHashString);
                var textToVerifyHashBytes = textToVerifyHashPayload.ToUTF8Bytes();

                return VerifyHash(textToVerifyHashBytes, verificationHashBytes);
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

        public HashResult VerifyFileHash(string filePathToVerifyHash, byte[] verificationHashBytes, LongOffsetOptions? offsetOptions = null)
        {
            if (verificationHashBytes is null || verificationHashBytes.Length == 0)
            {
                return new HashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_VerificationHashBytesRequired,
                };
            }

            var hashResult = ComputeFileHash(filePathToVerifyHash, offsetOptions);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(verificationHashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }

        public HashResult VerifyFileHash(string filePathToVerifyHash, string encodedVerificationHashString, LongOffsetOptions? offsetOptions = null)
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
                var verificationHashBytes = _encoder.DecodeString(encodedVerificationHashString);

                return VerifyFileHash(filePathToVerifyHash, verificationHashBytes, offsetOptions);
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

        public void Dispose() =>
            _hashAlgorithm?.Dispose();
    }
}