﻿using CryptographyHelpers.Encoding;
using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.Hash;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Options;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text;
using CryptographyHelpers.Utils;
using System;
using System.IO;
using System.Linq;
using System.Security.Authentication;

namespace CryptographyHelpers.HMAC
{
    public abstract class HMACBase : IHMAC
    {
        public event OnProgressHandler OnComputeFileHMACProgress;
        private const int FileReadBufferSize = 1024 * 4;
        private const EncodingType DefaultEncodingType = EncodingType.Hexadecimal;
        private readonly HashAlgorithmType _hashAlgorithmType;
        private readonly ServiceLocator _serviceLocator = ServiceLocator.Instance;


        public HMACBase(HashAlgorithmType hashAlgorithmType) =>
            _hashAlgorithmType = hashAlgorithmType;

        public HMACResult ComputeHMAC(string stringToComputeHMAC) =>
            ComputeHMAC(stringToComputeHMAC, key: null, keyAndOutputEncodingType: DefaultEncodingType, new OffsetOptions());

        public HMACResult ComputeHMAC(string stringToComputeHMAC, string key) =>
            ComputeHMAC(stringToComputeHMAC, key, keyAndOutputEncodingType: DefaultEncodingType, new OffsetOptions());

        public HMACResult ComputeHMAC(string stringToComputeHMAC, string key, EncodingType keyAndOutputEncodingType) =>
            ComputeHMAC(stringToComputeHMAC, key, keyAndOutputEncodingType, new OffsetOptions());

        public HMACResult ComputeHMAC(string stringToComputeHMAC, string key, EncodingType keyAndOutputEncodingType, OffsetOptions offsetOptions)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHMAC))
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_InputStringRequired,
                };
            }

            var stringToComputeHMACBytes = stringToComputeHMAC.ToUTF8Bytes();
            byte[] keyBytes = null;

            try
            {
                if (!string.IsNullOrWhiteSpace(key))
                {
                    keyBytes = keyAndOutputEncodingType == EncodingType.Hexadecimal
                        ? _serviceLocator.GetService<IHexadecimal>().DecodeString(key)
                        : _serviceLocator.GetService<IBase64>().DecodeString(key);
                }

                return ComputeHMAC(stringToComputeHMACBytes, keyBytes, keyAndOutputEncodingType, offsetOptions);
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

        public HMACResult ComputeHMAC(byte[] bytesToComputeHMAC) =>
            ComputeHMAC(bytesToComputeHMAC, key: null, outputEncodingType: DefaultEncodingType, new OffsetOptions());

        public HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, byte[] key) =>
            ComputeHMAC(bytesToComputeHMAC, key, outputEncodingType: DefaultEncodingType, new OffsetOptions());

        public HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, byte[] key, EncodingType outputEncodingType) =>
            ComputeHMAC(bytesToComputeHMAC, key, outputEncodingType, new OffsetOptions());

        public HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, byte[] key, EncodingType outputEncodingType, OffsetOptions offsetOptions)
        {
            if (bytesToComputeHMAC is null || bytesToComputeHMAC.Length == 0)
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_InputBytesRequired,
                };
            }

            try
            {
                if (key is null || key.Length == 0)
                {
                    key = CryptographyUtils.GenerateRandomBytes(HashUtils.HashAlgorithmOutputBytesSize[_hashAlgorithmType]);
                }

                using var hmacAlgorithm = System.Security.Cryptography.HMAC.Create($"HMAC{_hashAlgorithmType}");
                hmacAlgorithm.Key = key;
                var count = offsetOptions.Count == 0 ? bytesToComputeHMAC.Length : offsetOptions.Count;
                var hashBytes = hmacAlgorithm.ComputeHash(bytesToComputeHMAC, offsetOptions.Offset, count);

                return new()
                {
                    Success = true,
                    Message = MessageStrings.HMAC_ComputeSuccess,
                    HashAlgorithmType = _hashAlgorithmType,
                    Key = key,
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


        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC) =>
            ComputeFileHMAC(filePathToComputeHMAC, key: null, outputEncodingType: DefaultEncodingType, new LongOffsetOptions());

        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, string key) =>
            ComputeFileHMAC(filePathToComputeHMAC, key, keyAndOutputEncodingType: DefaultEncodingType, new LongOffsetOptions());

        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, string key, EncodingType outputEncodingType) =>
            ComputeFileHMAC(filePathToComputeHMAC, key, outputEncodingType, new LongOffsetOptions());

        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, string key, EncodingType keyAndOutputEncodingType, LongOffsetOptions offsetOptions)
        {
            byte[] keyBytes = null;

            try
            {
                if (!string.IsNullOrWhiteSpace(key))
                {
                    keyBytes = keyAndOutputEncodingType == EncodingType.Hexadecimal
                        ? _serviceLocator.GetService<IHexadecimal>().DecodeString(key)
                        : _serviceLocator.GetService<IBase64>().DecodeString(key);
                }

                return ComputeFileHMAC(filePathToComputeHMAC, keyBytes, keyAndOutputEncodingType, offsetOptions);
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

        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, byte[] key) =>
            ComputeFileHMAC(filePathToComputeHMAC, key, outputEncodingType: DefaultEncodingType, new LongOffsetOptions());

        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, byte[] key, EncodingType outputEncodingType) =>
            ComputeFileHMAC(filePathToComputeHMAC, key, outputEncodingType, new LongOffsetOptions());

        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, byte[] key, EncodingType outputEncodingType, LongOffsetOptions offsetOptions)
        {
            if (!File.Exists(filePathToComputeHMAC))
            {
                return new()
                {
                    Success = false,
                    Message = $@"{MessageStrings.File_PathNotFound} ""{filePathToComputeHMAC}"".",
                };
            }

            try
            {
                if (key == null || key.Length == 0)
                {
                    key = CryptographyUtils.GenerateRandomBytes(HashUtils.HashAlgorithmOutputBytesSize[_hashAlgorithmType]);
                }

                using var fileStream = new FileStream(filePathToComputeHMAC, FileMode.Open, FileAccess.Read, FileShare.None);
                var count = offsetOptions.Count == 0 ? fileStream.Length : offsetOptions.Count;
                fileStream.Position = offsetOptions.Offset;
                var buffer = new byte[FileReadBufferSize];
                var bytesToRead = (count - offsetOptions.Offset);
                using var hmacAlgorithm = System.Security.Cryptography.HMAC.Create($"HMAC{_hashAlgorithmType}");
                hmacAlgorithm.Key = key;
                var percentageDone = 0;

                while (bytesToRead > 0)
                {
                    var bytesRead = fileStream.Read(buffer, 0, (int)Math.Min(buffer.Length, bytesToRead));

                    if (bytesRead > 0)
                    {
                        bytesToRead -= bytesRead;

                        if (bytesToRead > 0)
                        {
                            hmacAlgorithm.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                        }
                        else
                        {
                            hmacAlgorithm.TransformFinalBlock(buffer, 0, bytesRead);
                        }

                        var tmpPercentageDone = (int)(fileStream.Position * 100 / count);

                        if (tmpPercentageDone != percentageDone)
                        {
                            percentageDone = tmpPercentageDone;

                            OnComputeFileHMACProgress?.Invoke(percentageDone, (percentageDone != 100 ? $"Computing HMAC ({percentageDone}%)..." : $"HMAC computed ({percentageDone}%)."));
                        }
                    }
                }

                return new()
                {
                    Success = true,
                    Message = MessageStrings.HMAC_ComputeSuccess,
                    HashAlgorithmType = _hashAlgorithmType,
                    Key = key,
                    HashBytes = hmacAlgorithm.Hash,
                    HashString = outputEncodingType == EncodingType.Hexadecimal
                        ? _serviceLocator.GetService<IHexadecimal>().EncodeToString(hmacAlgorithm.Hash)
                        : _serviceLocator.GetService<IBase64>().EncodeToString(hmacAlgorithm.Hash),
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


        public HMACResult VerifyHMAC(string stringToVerifyHMAC, string key, string verificationHMACString) =>
            VerifyHMAC(stringToVerifyHMAC, key, verificationHMACString, keyAndVerificationHMACStringEncodingType: DefaultEncodingType, new OffsetOptions());

        public HMACResult VerifyHMAC(string stringToVerifyHMAC, string key, string verificationHMACString, EncodingType keyAndVerificationHMACStringEncodingType) =>
            VerifyHMAC(stringToVerifyHMAC, key, verificationHMACString, keyAndVerificationHMACStringEncodingType, new OffsetOptions());

        public HMACResult VerifyHMAC(string stringToVerifyHMAC, string key, string verificationHMACString, EncodingType keyAndVerificationHMACStringEncodingType, OffsetOptions offsetOptions)
        {
            if (string.IsNullOrWhiteSpace(stringToVerifyHMAC))
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_InputStringRequired,
                };
            }

            if (string.IsNullOrWhiteSpace(key))
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_InputKeyStringRequired,
                };
            }

            if (string.IsNullOrWhiteSpace(verificationHMACString))
            {
                return new()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_VerificationHMACStringRequired,
                };
            }

            var stringToVerifyHMACBytes = stringToVerifyHMAC.ToUTF8Bytes();

            try
            {
                var keyBytes = keyAndVerificationHMACStringEncodingType == EncodingType.Hexadecimal
                    ? _serviceLocator.GetService<IHexadecimal>().DecodeString(key)
                    : _serviceLocator.GetService<IBase64>().DecodeString(key);
                var verificationHMACBytes = keyAndVerificationHMACStringEncodingType == EncodingType.Hexadecimal
                    ? _serviceLocator.GetService<IHexadecimal>().DecodeString(verificationHMACString)
                    : _serviceLocator.GetService<IBase64>().DecodeString(verificationHMACString);

                return VerifyHMAC(stringToVerifyHMACBytes, keyBytes, verificationHMACBytes, keyAndVerificationHMACStringEncodingType, offsetOptions);
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

        public HMACResult VerifyHMAC(byte[] bytesToVerifyHMAC, byte[] key, byte[] verificationHMACBytes) =>
            VerifyHMAC(bytesToVerifyHMAC, key, verificationHMACBytes, DefaultEncodingType, new OffsetOptions());

        public HMACResult VerifyHMAC(byte[] bytesToVerifyHMAC, byte[] key, byte[] verificationHMACBytes, EncodingType outputEncodingType) =>
            VerifyHMAC(bytesToVerifyHMAC, key, verificationHMACBytes, outputEncodingType, new OffsetOptions());

        public HMACResult VerifyHMAC(byte[] bytesToVerifyHMAC, byte[] key, byte[] verificationHMACBytes, EncodingType outputEncodingType, OffsetOptions offsetOptions)
        {
            var HMACResult = ComputeHMAC(bytesToVerifyHMAC, key, outputEncodingType, offsetOptions);

            if (HMACResult.Success)
            {
                var hashesMatch = HMACResult.HashBytes.SequenceEqual(verificationHMACBytes);

                HMACResult.Success = hashesMatch;
                HMACResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return HMACResult;
        }


        public HMACResult VerifyFileHMAC(string filePathToVerifyHMAC, string key, string verificationHMACString, EncodingType keyAndVerificationHMACStringEncodingType, LongOffsetOptions offsetOptions)
        {
            try
            {
                var keyBytes = keyAndVerificationHMACStringEncodingType == EncodingType.Hexadecimal
                    ? _serviceLocator.GetService<IHexadecimal>().DecodeString(key)
                    : _serviceLocator.GetService<IBase64>().DecodeString(key);
                var verificationHMACBytes = keyAndVerificationHMACStringEncodingType == EncodingType.Hexadecimal
                    ? _serviceLocator.GetService<IHexadecimal>().DecodeString(verificationHMACString)
                    : _serviceLocator.GetService<IBase64>().DecodeString(verificationHMACString);

                return VerifyFileHMAC(filePathToVerifyHMAC, keyBytes, verificationHMACBytes, keyAndVerificationHMACStringEncodingType, offsetOptions);
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

        public HMACResult VerifyFileHMAC(string filePathToVerifyHMAC, byte[] key, byte[] verificationHMACBytes, EncodingType outputEncodingType, LongOffsetOptions offsetOptions)
        {
            var hmacResult = ComputeFileHMAC(filePathToVerifyHMAC, key, outputEncodingType, offsetOptions);

            if (hmacResult.Success)
            {
                var hashesMatch = hmacResult.HashBytes.SequenceEqual(verificationHMACBytes);

                hmacResult.Success = hashesMatch;
                hmacResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hmacResult;
        }
    }
}