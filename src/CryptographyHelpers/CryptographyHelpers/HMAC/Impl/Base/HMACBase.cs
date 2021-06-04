using CryptographyHelpers.Encoding;
using CryptographyHelpers.Encoding.Enums;
using CryptographyHelpers.EventHandlers;
using CryptographyHelpers.Extensions;
using CryptographyHelpers.HMAC.Enums;
using CryptographyHelpers.HMAC.Results;
using CryptographyHelpers.HMAC.Util;
using CryptographyHelpers.Options;
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
        public event OnProgressHandler OnProgress;
        private const int FileReadBufferSize = 1024 * 4;
        private const EncodingType DefaultEncodingType = EncodingType.Hexadecimal;
        private readonly HMACAlgorithmType _hmacAlgorithmType;


        public HMACBase(HMACAlgorithmType hmacAlgorithmType) =>
            _hmacAlgorithmType = hmacAlgorithmType;


        [ExcludeFromCodeCoverage]
        public HMACResult ComputeHMAC(string stringToComputeHMAC) =>
            ComputeHMAC(stringToComputeHMAC, key: null, new SeekOptions(), DefaultEncodingType);

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeHMAC(string stringToComputeHMAC, byte[] key) =>
            ComputeHMAC(stringToComputeHMAC, key, new SeekOptions(), DefaultEncodingType);

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeHMAC(string stringToComputeHMAC, byte[] key, SeekOptions seekOptions) =>
            ComputeHMAC(stringToComputeHMAC, key, seekOptions, DefaultEncodingType);

        public HMACResult ComputeHMAC(string stringToComputeHMAC, byte[] key, SeekOptions seekOptions, EncodingType outputEncodingType)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHMAC))
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_InputStringRequired
                };
            }

            var stringToComputeHMACBytes = stringToComputeHMAC.ToUTF8Bytes();

            return ComputeHMAC(stringToComputeHMACBytes, key, seekOptions, outputEncodingType);
        }

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeHMAC(byte[] bytesToComputeHMAC) =>
            ComputeHMAC(bytesToComputeHMAC, key: null, new SeekOptions(), DefaultEncodingType);

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, byte[] key) =>
            ComputeHMAC(bytesToComputeHMAC, key, new SeekOptions(), DefaultEncodingType);

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, byte[] key, SeekOptions seekOptions) =>
            ComputeHMAC(bytesToComputeHMAC, key, seekOptions, DefaultEncodingType);

        public HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, byte[] key, SeekOptions seekOptions, EncodingType outputEncodingType)
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
                    key = CryptographyCommon.GenerateRandomBytes(HMACUtil.HMACSizeMapper[_hmacAlgorithmType] / 8);
                }

                using var hmacAlgorithm = (System.Security.Cryptography.HMAC)CryptoConfig.CreateFromName(_hmacAlgorithmType.ToString());
                hmacAlgorithm.Key = key;
                var count = (seekOptions.Count == 0 ? bytesToComputeHMAC.Length : seekOptions.Count);
                var hashBytes = hmacAlgorithm.ComputeHash(bytesToComputeHMAC, seekOptions.Offset, count);

                return new HMACResult()
                {
                    Success = true,
                    Message = MessageStrings.HMAC_ComputeSuccess,
                    HMACAlgorithmType = _hmacAlgorithmType,
                    Key = key,
                    OutputEncodingType = outputEncodingType,
                    HashBytes = hashBytes,
                    HashString = outputEncodingType == EncodingType.Hexadecimal
                        ? Hexadecimal.ToHexadecimalString(hashBytes)
                        : Base64.ToBase64String(hashBytes),
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
            ComputeFileHMAC(filePathToComputeHMAC, key: null, new LongSeekOptions(), DefaultEncodingType);

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, byte[] key) =>
            ComputeFileHMAC(filePathToComputeHMAC, key, new LongSeekOptions(), DefaultEncodingType);

        [ExcludeFromCodeCoverage]
        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, byte[] key, LongSeekOptions seekOptions) =>
            ComputeFileHMAC(filePathToComputeHMAC, key, seekOptions, DefaultEncodingType);

        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, byte[] key, LongSeekOptions seekOptions, EncodingType outputEncodingType)
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
                    key = CryptographyCommon.GenerateRandomBytes(HMACUtil.HMACSizeMapper[_hmacAlgorithmType] / 8);
                }

                byte[] hashBytes = null;

                using (var fStream = new FileStream(filePathToComputeHMAC, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    var count = seekOptions.Count == 0 ? fStream.Length : seekOptions.Count;
                    fStream.Position = seekOptions.Offset;
                    var buffer = new byte[FileReadBufferSize];
                    var amount = (count - seekOptions.Offset);

                    using (var hmacAlgorithm = (System.Security.Cryptography.HMAC)CryptoConfig.CreateFromName(_hmacAlgorithmType.ToString()))
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

                                    RaiseOnProgressEvent(percentageDone, (percentageDone != 100 ? $"Computing HMAC ({percentageDone}%)..." : $"HMAC computed ({percentageDone}%)."));
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
                    HMACAlgorithmType = _hmacAlgorithmType,
                    Key = key,
                    OutputEncodingType = outputEncodingType,
                    HashBytes = hashBytes,
                    HashString = outputEncodingType == EncodingType.Hexadecimal
                        ? Hexadecimal.ToHexadecimalString(hashBytes)
                        : Base64.ToBase64String(hashBytes),
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


        public HMACResult VerifyHMAC(byte[] bytesToVerifyHMAC, byte[] key, byte[] verificationHMACBytes) =>
            VerifyHMAC(bytesToVerifyHMAC, key, verificationHMACBytes, new SeekOptions());

        [ExcludeFromCodeCoverage]
        public HMACResult VerifyHMAC(byte[] bytesToVerifyHMAC, byte[] key, byte[] verificationHMACBytes, SeekOptions seekOptions)
        {
            var HMACResult = ComputeHMAC(bytesToVerifyHMAC, key, seekOptions);

            if (HMACResult.Success)
            {
                var hashesMatch = HMACResult.HashBytes.SequenceEqual(verificationHMACBytes);

                HMACResult.Success = hashesMatch;
                HMACResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return HMACResult;
        }

        public HMACResult VerifyHMAC(string stringToVerifyHMAC, string key, string verificationHMACString, SeekOptions seekOptions, EncodingType keyAndVerificationKeyEncodingType)
        {
            var stringToVerifyHMACBytes = stringToVerifyHMAC.ToUTF8Bytes();
            var keyBytes = keyAndVerificationKeyEncodingType == EncodingType.Hexadecimal
                ? Hexadecimal.ToByteArray(key)
                : Base64.ToByteArray(key);
            var verificationHMACBytes = keyAndVerificationKeyEncodingType == EncodingType.Hexadecimal 
                ? Hexadecimal.ToByteArray(verificationHMACString)
                : Base64.ToByteArray(verificationHMACString);

            return VerifyHMAC(stringToVerifyHMACBytes, keyBytes, verificationHMACBytes);
        }

        
        public HMACResult VerifyFileHMAC(string filePathToVerifyHMAC, byte[] key, string verificationHMACString, LongSeekOptions seekOptions)
        {
            var hmacBytes = Encoding.Hexadecimal.ToByteArray(verificationHMACString);

            return VerifyFileHMAC(hmacBytes, filePathToVerifyHMAC, seekOptions, key);
        }

        public HMACResult VerifyFileHMAC(byte[] hmacBytes, string filePathToVerifyHMAC, LongSeekOptions seekOptions, byte[] key)
        {
            var hmacResult = ComputeFileHMAC(filePathToVerifyHMAC, seekOptions, key);

            if (hmacResult.Success)
            {
                var hashesMatch = hmacResult.HashBytes.SequenceEqual(hmacBytes);

                hmacResult.Success = hashesMatch;
                hmacResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hmacResult;
        }


        [ExcludeFromCodeCoverage]
        private void RaiseOnProgressEvent(int percentageDone, string message) =>
            OnProgress?.Invoke(percentageDone, message);
    }
}
