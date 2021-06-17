using CryptographyHelpers.Encoding;
using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.Extensions;
using CryptographyHelpers.Hash;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using System;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

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


        [ExcludeFromCodeCoverage]
        public HMACResult ComputeHMAC(string stringToComputeHMAC) =>
            ComputeHMAC(stringToComputeHMAC, key: null, keyAndOutputEncodingType: DefaultEncodingType, new SeekOptions());

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeHMAC(string stringToComputeHMAC, string key) =>
            ComputeHMAC(stringToComputeHMAC, key, keyAndOutputEncodingType: DefaultEncodingType, new SeekOptions());

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeHMAC(string stringToComputeHMAC, string key, EncodingType keyAndOutputEncodingType) =>
            ComputeHMAC(stringToComputeHMAC, key, keyAndOutputEncodingType, new SeekOptions());

        public HMACResult ComputeHMAC(string stringToComputeHMAC, string key, EncodingType keyAndOutputEncodingType, SeekOptions seekOptions)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHMAC))
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_InputStringRequired
                };
            }

            try
            {
                var stringToComputeHMACBytes = stringToComputeHMAC.ToUTF8Bytes();
                byte[] keyBytes = null;

                if (!string.IsNullOrWhiteSpace(key))
                {
                    keyBytes = keyAndOutputEncodingType == EncodingType.Hexadecimal
                        ? _serviceLocator.GetService<IHexadecimal>().DecodeString(key)
                        : _serviceLocator.GetService<IBase64>().DecodeString(key);
                }

                return ComputeHMAC(stringToComputeHMACBytes, keyBytes, keyAndOutputEncodingType, seekOptions);
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

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeHMAC(byte[] bytesToComputeHMAC) =>
            ComputeHMAC(bytesToComputeHMAC, key: null, outputEncodingType: DefaultEncodingType, new SeekOptions());

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, byte[] key) =>
            ComputeHMAC(bytesToComputeHMAC, key, outputEncodingType: DefaultEncodingType, new SeekOptions());

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, byte[] key, EncodingType outputEncodingType) =>
            ComputeHMAC(bytesToComputeHMAC, key, outputEncodingType, new SeekOptions());

        public HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, byte[] key, EncodingType outputEncodingType, SeekOptions seekOptions)
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
                if (key is null || key.Length == 0)
                {
                    key = CryptographyCommon.GenerateRandomBytes(HashUtil.HashAlgorithmOutputBytesSizeMapper[_hashAlgorithmType]);
                }

                using var hmacAlgorithm = (System.Security.Cryptography.HMAC)CryptoConfig.CreateFromName($"HMAC{_hashAlgorithmType}");
                hmacAlgorithm.Key = key;
                var count = (seekOptions.Count == 0 ? bytesToComputeHMAC.Length : seekOptions.Count);
                var hashBytes = hmacAlgorithm.ComputeHash(bytesToComputeHMAC, seekOptions.Offset, count);

                return new HMACResult()
                {
                    Success = true,
                    Message = MessageStrings.HMAC_ComputeSuccess,
                    HashAlgorithmType = _hashAlgorithmType,
                    Key = key,
                    OutputEncodingType = outputEncodingType,
                    HashBytes = hashBytes,
                    HashString = outputEncodingType == EncodingType.Hexadecimal
                        ? _serviceLocator.GetService<IHexadecimal>().EncodeToString(hashBytes)
                        : _serviceLocator.GetService<IBase64>().EncodeToString(hashBytes),
                };
            }
            catch (Exception ex)
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }
        }


        [ExcludeFromCodeCoverage]
        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC) =>
            ComputeFileHMAC(filePathToComputeHMAC, key: null, outputEncodingType: DefaultEncodingType, new LongSeekOptions());

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, string key) =>
            ComputeFileHMAC(filePathToComputeHMAC, key, keyAndOutputEncodingType: DefaultEncodingType, new LongSeekOptions());

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, string key, EncodingType outputEncodingType) =>
            ComputeFileHMAC(filePathToComputeHMAC, key, outputEncodingType, new LongSeekOptions());

        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, string key, EncodingType keyAndOutputEncodingType, LongSeekOptions seekOptions)
        {
            try
            {
                byte[] keyBytes = null;

                if (!string.IsNullOrWhiteSpace(key))
                {
                    keyBytes = keyAndOutputEncodingType == EncodingType.Hexadecimal
                        ? _serviceLocator.GetService<IHexadecimal>().DecodeString(key)
                        : _serviceLocator.GetService<IBase64>().DecodeString(key);
                }

                return ComputeFileHMAC(filePathToComputeHMAC, keyBytes, keyAndOutputEncodingType, seekOptions);
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

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, byte[] key) =>
            ComputeFileHMAC(filePathToComputeHMAC, key, outputEncodingType: DefaultEncodingType, new LongSeekOptions());

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, byte[] key, EncodingType outputEncodingType) =>
            ComputeFileHMAC(filePathToComputeHMAC, key, outputEncodingType, new LongSeekOptions());

        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, byte[] key, EncodingType outputEncodingType, LongSeekOptions seekOptions)
        {
            if (!File.Exists(filePathToComputeHMAC))
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = $@"{MessageStrings.File_PathNotFound} ""{filePathToComputeHMAC}""."
                };
            }

            try
            {
                if (key == null || key.Length == 0)
                {
                    key = CryptographyCommon.GenerateRandomBytes(HashUtil.HashAlgorithmOutputBytesSizeMapper[_hashAlgorithmType]);
                }

                byte[] hashBytes = null;

                using (var fStream = new FileStream(filePathToComputeHMAC, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    var count = seekOptions.Count == 0 ? fStream.Length : seekOptions.Count;
                    fStream.Position = seekOptions.Offset;
                    var buffer = new byte[FileReadBufferSize];
                    var amount = (count - seekOptions.Offset);

                    using (var hmacAlgorithm = (System.Security.Cryptography.HMAC)CryptoConfig.CreateFromName($"HMAC{_hashAlgorithmType}"))
                    {
                        hmacAlgorithm.Key = key;
                        var percentageDone = 0;

                        while (amount > 0)
                        {
                            var bytesRead = fStream.Read(buffer, 0, (int)Math.Min(buffer.Length, amount));

                            if (bytesRead > 0)
                            {
                                amount -= bytesRead;

                                if (amount > 0)
                                {
                                    hmacAlgorithm.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                                }
                                else
                                {
                                    hmacAlgorithm.TransformFinalBlock(buffer, 0, bytesRead);
                                }

                                var tmpPercentageDone = (int)(fStream.Position * 100 / count);

                                if (tmpPercentageDone != percentageDone)
                                {
                                    percentageDone = tmpPercentageDone;

                                    OnComputeFileHMACProgress?.Invoke(percentageDone, (percentageDone != 100 ? $"Computing HMAC ({percentageDone}%)..." : $"HMAC computed ({percentageDone}%)."));
                                }
                            }
                            else
                            {
                                throw new InvalidOperationException();
                            }
                        }

                        hashBytes = hmacAlgorithm.Hash;
                    }
                }

                return new HMACResult()
                {
                    Success = true,
                    Message = MessageStrings.HMAC_ComputeSuccess,
                    HashAlgorithmType = _hashAlgorithmType,
                    Key = key,
                    OutputEncodingType = outputEncodingType,
                    HashBytes = hashBytes,
                    HashString = outputEncodingType == EncodingType.Hexadecimal
                        ? _serviceLocator.GetService<IHexadecimal>().EncodeToString(hashBytes)
                        : _serviceLocator.GetService<IBase64>().EncodeToString(hashBytes),
                };
            }
            catch (Exception ex)
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }
        }


        [ExcludeFromCodeCoverage]
        public HMACResult VerifyHMAC(string stringToVerifyHMAC, string key, string verificationHMACString) =>
            VerifyHMAC(stringToVerifyHMAC, key, verificationHMACString, keyAndVerificationHMACStringEncodingType: DefaultEncodingType, new SeekOptions());

        [ExcludeFromCodeCoverage]
        public HMACResult VerifyHMAC(string stringToVerifyHMAC, string key, string verificationHMACString, EncodingType keyAndVerificationHMACStringEncodingType) =>
            VerifyHMAC(stringToVerifyHMAC, key, verificationHMACString, keyAndVerificationHMACStringEncodingType, new SeekOptions());

        public HMACResult VerifyHMAC(string stringToVerifyHMAC, string key, string verificationHMACString, EncodingType keyAndVerificationHMACStringEncodingType, SeekOptions seekOptions)
        {
            if (string.IsNullOrWhiteSpace(stringToVerifyHMAC))
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_InputStringRequired,
                };
            }

            if (string.IsNullOrWhiteSpace(key))
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_InputKeyStringRequired,
                };
            }

            if (string.IsNullOrWhiteSpace(verificationHMACString))
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_VerificationHMACStringRequired,
                };
            }

            try
            {
                var stringToVerifyHMACBytes = stringToVerifyHMAC.ToUTF8Bytes();
                var keyBytes = keyAndVerificationHMACStringEncodingType == EncodingType.Hexadecimal
                    ? _serviceLocator.GetService<IHexadecimal>().DecodeString(key)
                    : _serviceLocator.GetService<IBase64>().DecodeString(key);
                var verificationHMACBytes = keyAndVerificationHMACStringEncodingType == EncodingType.Hexadecimal
                    ? _serviceLocator.GetService<IHexadecimal>().DecodeString(verificationHMACString)
                    : _serviceLocator.GetService<IBase64>().DecodeString(verificationHMACString);

                return VerifyHMAC(stringToVerifyHMACBytes, keyBytes, verificationHMACBytes, seekOptions);
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

        [ExcludeFromCodeCoverage]
        public HMACResult VerifyHMAC(byte[] bytesToVerifyHMAC, byte[] key, byte[] verificationHMACBytes) =>
            VerifyHMAC(bytesToVerifyHMAC, key, verificationHMACBytes, new SeekOptions());

        public HMACResult VerifyHMAC(byte[] bytesToVerifyHMAC, byte[] key, byte[] verificationHMACBytes, SeekOptions seekOptions)
        {
            var HMACResult = ComputeHMAC(bytesToVerifyHMAC, key, DefaultEncodingType, seekOptions);

            if (HMACResult.Success)
            {
                var hashesMatch = HMACResult.HashBytes.SequenceEqual(verificationHMACBytes);

                HMACResult.Success = hashesMatch;
                HMACResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return HMACResult;
        }

        
        public HMACResult VerifyFileHMAC(string filePathToVerifyHMAC, string key, string verificationHMACString, EncodingType keyAndVerificationHMACStringEncodingType, LongSeekOptions seekOptions)
        {
            try
            {
                var keyBytes = keyAndVerificationHMACStringEncodingType == EncodingType.Hexadecimal
                    ? _serviceLocator.GetService<IHexadecimal>().DecodeString(key)
                    : _serviceLocator.GetService<IBase64>().DecodeString(key);
                var verificationHMACBytes = keyAndVerificationHMACStringEncodingType == EncodingType.Hexadecimal
                    ? _serviceLocator.GetService<IHexadecimal>().DecodeString(verificationHMACString)
                    : _serviceLocator.GetService<IBase64>().DecodeString(verificationHMACString);

                return VerifyFileHMAC(filePathToVerifyHMAC, keyBytes, verificationHMACBytes, seekOptions);
            }
            catch (Exception ex)
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }
        }

        public HMACResult VerifyFileHMAC(string filePathToVerifyHMAC, byte[] key, byte[] verificationHMACBytes, LongSeekOptions seekOptions)
        {
            var hmacResult = ComputeFileHMAC(filePathToVerifyHMAC, key, DefaultEncodingType, seekOptions);

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
