using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.Hash;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using System;
using System.IO;
using System.Linq;
using System.Security.Authentication;

namespace CryptographyHelpers.HMAC
{
    public class HMACBase : IHMAC
    {
        public event OnProgressHandler OnComputeFileHMACProgress;

        private readonly System.Security.Cryptography.HMAC _hmacAlgorithm;
        private readonly HashAlgorithmType _hashAlgorithmType;
        private readonly EncodingType _encodingType = EncodingType.Hexadecimal;
        private readonly IEncoder _encoder;
        private readonly int _bufferSizeInKBForFileHashing = 4 * Constants.BytesPerKilobyte;
        private readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;


        public HMACBase(HashAlgorithmType hashAlgorithmType, byte[] key = null, EncodingType? encodingType = null, int? bufferSizeInKBForFileHashing = null)
        {
            _hashAlgorithmType = hashAlgorithmType;
            _hmacAlgorithm = System.Security.Cryptography.HMAC.Create($"HMAC{_hashAlgorithmType}");
            _hmacAlgorithm.Key = key ?? CryptographyUtils.GenerateRandomBytes(HashUtils.HashAlgorithmOutputBytesSize[_hashAlgorithmType]);
            _encodingType = encodingType ?? _encodingType;
            _encoder = _encodingType switch
            {
                EncodingType.Hexadecimal => _serviceLocator.GetService<IHexadecimal>(),
                EncodingType.Base64 => _serviceLocator.GetService<IBase64>(),
                _ => throw new InvalidOperationException($@"Unexpected enum value ""{_encodingType}"" of type {typeof(EncodingType)}."),
            };
            _bufferSizeInKBForFileHashing = bufferSizeInKBForFileHashing ?? _bufferSizeInKBForFileHashing;
        }

        public HMACBase(HashAlgorithmType hashAlgorithmType, string encodedKey = null, EncodingType? encodingType = null, int? bufferSizeInKBForFileHashing = null)
        {
            _encodingType = encodingType ?? _encodingType;
            _encoder = _encodingType switch
            {
                EncodingType.Hexadecimal => _serviceLocator.GetService<IHexadecimal>(),
                EncodingType.Base64 => _serviceLocator.GetService<IBase64>(),
                _ => throw new InvalidOperationException($@"Unexpected enum value ""{_encodingType}"" of type {typeof(EncodingType)}."),
            };
            _hashAlgorithmType = hashAlgorithmType;
            _hmacAlgorithm = System.Security.Cryptography.HMAC.Create($"HMAC{_hashAlgorithmType}");
            var key = string.IsNullOrWhiteSpace(encodedKey)
                ? CryptographyUtils.GenerateRandomBytes(HashUtils.HashAlgorithmOutputBytesSize[_hashAlgorithmType])
                : _encoder.DecodeString(encodedKey);
            _hmacAlgorithm.Key = key;
            _bufferSizeInKBForFileHashing = bufferSizeInKBForFileHashing ?? _bufferSizeInKBForFileHashing;
        }


        public HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, OffsetOptions? offsetOptions = null)
        {
            if (bytesToComputeHMAC is null || bytesToComputeHMAC.Length == 0)
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_InputBytesRequired,
                };
            }

            try
            {
                var offset = offsetOptions.HasValue ? offsetOptions.Value.Offset : 0;
                var totalBytesToRead = offsetOptions.HasValue
                    ? offsetOptions.Value.Count == 0 ? bytesToComputeHMAC.Length : offsetOptions.Value.Count
                    : bytesToComputeHMAC.Length;
                var hashBytes = _hmacAlgorithm.ComputeHash(bytesToComputeHMAC, offset, totalBytesToRead);

                return new HMACResult()
                {
                    Success = true,
                    Message = MessageStrings.HMAC_ComputeSuccess,
                    HashAlgorithmType = _hashAlgorithmType,
                    Key = _hmacAlgorithm.Key,
                    HashBytes = hashBytes,
                    HashString = _encoder.EncodeToString(hashBytes),
                    HashStringEncodingType = _encodingType,
                };
            }
            catch (Exception ex)
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public HMACResult ComputeTextHMAC(string textToComputeHMAC, OffsetOptions? offsetOptions = null)
        {
            if (string.IsNullOrWhiteSpace(textToComputeHMAC))
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_InputTextRequired,
                };
            }

            try
            {
                var offset = offsetOptions.HasValue ? offsetOptions.Value.Offset : 0;
                var totalCharsToRead = offsetOptions.HasValue
                    ? offsetOptions.Value.Count == 0 ? textToComputeHMAC.Length : offsetOptions.Value.Count
                    : textToComputeHMAC.Length;
                var textToComputeHashPayload = textToComputeHMAC.Substring(offset, totalCharsToRead);
                var textToComputeHashPayloadBytes = textToComputeHashPayload.ToUTF8Bytes();

                return ComputeHMAC(textToComputeHashPayloadBytes);
            }
            catch (Exception ex)
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, LongOffsetOptions? offsetOptions = null)
        {
            if (!File.Exists(filePathToComputeHMAC))
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = $@"{MessageStrings.File_PathNotFound} ""{filePathToComputeHMAC}"".",
                };
            }

            try
            {
                using (var fileStream = new FileStream(filePathToComputeHMAC, FileMode.Open, FileAccess.Read, FileShare.None))
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

                    while (totalBytesNotRead > 0)
                    {
                        var bytesRead = fileStream.Read(buffer, 0, (int)Math.Min(buffer.Length, totalBytesNotRead));

                        if (bytesRead > 0L)
                        {
                            if (totalBytesRead > 0)
                            {
                                _hmacAlgorithm.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                            }
                            else
                            {
                                _hmacAlgorithm.TransformFinalBlock(buffer, 0, bytesRead);
                            }

                            totalBytesRead += bytesRead;
                            totalBytesNotRead -= bytesRead;

                            var tmpPercentageDone = (int)(fileStream.Position * 100 / totalBytesToRead);

                            if (tmpPercentageDone != percentageDone)
                            {
                                percentageDone = tmpPercentageDone;

                                OnComputeFileHMACProgress?.Invoke(percentageDone, (percentageDone != 100 ? $"Computing HMAC ({percentageDone}%)..." : $"HMAC computed ({percentageDone}%)."));
                            }
                        }
                    }
                }

                return new HMACResult()
                {
                    Success = true,
                    Message = MessageStrings.HMAC_ComputeSuccess,
                    HashAlgorithmType = _hashAlgorithmType,
                    Key = _hmacAlgorithm.Key,
                    HashBytes = _hmacAlgorithm.Hash,
                    HashString = _encoder.EncodeToString(_hmacAlgorithm.Hash),
                    HashStringEncodingType = _encodingType,
                };
            }
            catch (Exception ex)
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public HMACResult VerifyHMAC(byte[] bytesToVerifyHMAC, byte[] verificationHMACBytes, OffsetOptions? offsetOptions = null)
        {
            if (verificationHMACBytes is null || verificationHMACBytes.Length == 0)
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_VerificationHMACBytesRequired,
                };
            }

            var HMACResult = ComputeHMAC(bytesToVerifyHMAC, offsetOptions);

            if (HMACResult.Success)
            {
                var hashesMatch = HMACResult.HashBytes.SequenceEqual(verificationHMACBytes);

                HMACResult.Success = hashesMatch;
                HMACResult.Message = $"{(hashesMatch ? MessageStrings.HMAC_Match : MessageStrings.HMAC_DoesNotMatch)}";
            }

            return HMACResult;
        }

        public HMACResult VerifyTextHMAC(string textToVerifyHMAC, string encodedVerificationHMACString, OffsetOptions? offsetOptions = null)
        {
            if (string.IsNullOrWhiteSpace(textToVerifyHMAC))
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_InputTextRequired,
                };
            }

            try
            {
                var offset = offsetOptions.HasValue ? offsetOptions.Value.Offset : 0;
                var totalCharsToRead = offsetOptions.HasValue
                    ? offsetOptions.Value.Count == 0 ? textToVerifyHMAC.Length : offsetOptions.Value.Count
                    : textToVerifyHMAC.Length;
                var textToVerifyHMACPayload = textToVerifyHMAC.Substring(offset, totalCharsToRead);
                var verificationHMACBytes = _encoder.DecodeString(encodedVerificationHMACString);
                var textToVerifyHMACBytes = textToVerifyHMACPayload.ToUTF8Bytes();

                return VerifyHMAC(textToVerifyHMACBytes, verificationHMACBytes);
            }
            catch (Exception ex)
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public HMACResult VerifyFileHMAC(string filePathToVerifyHMAC, byte[] verificationHMACBytes, LongOffsetOptions? offsetOptions = null)
        {
            if (verificationHMACBytes is null || verificationHMACBytes.Length == 0)
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_VerificationHMACBytesRequired,
                };
            }

            var hmacResult = ComputeFileHMAC(filePathToVerifyHMAC, offsetOptions);

            if (hmacResult.Success)
            {
                var hashesMatch = hmacResult.HashBytes.SequenceEqual(verificationHMACBytes);

                hmacResult.Success = hashesMatch;
                hmacResult.Message = $"{(hashesMatch ? MessageStrings.HMAC_Match : MessageStrings.HMAC_DoesNotMatch)}";
            }

            return hmacResult;
        }

        public HMACResult VerifyFileHMAC(string filePathToVerifyHMAC, string encodedVerificationHMACString, LongOffsetOptions offsetOptions)
        {
            if (string.IsNullOrWhiteSpace(encodedVerificationHMACString))
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_VerificationHMACStringRequired,
                };
            }

            try
            {
                var verificationHMACBytes = _encoder.DecodeString(encodedVerificationHMACString);

                return VerifyFileHMAC(filePathToVerifyHMAC, verificationHMACBytes, offsetOptions);
            }
            catch (Exception ex)
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public void Dispose() =>
            _hmacAlgorithm?.Dispose();
    }
}