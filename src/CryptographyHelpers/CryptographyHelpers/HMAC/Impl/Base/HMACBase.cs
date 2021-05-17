using CryptographyHelpers.Encoding;
using CryptographyHelpers.Hash;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Util;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CryptographyHelpers.HMAC
{
    public abstract class HMACBase : IHMAC
    {
        public event OnHashProgressHandler OnHMACProgress;
        private const int FileReadBufferSize = 1024 * 4;
        private HMACAlgorithmType _hmacAlgorithmType;

        public HMACBase(HMACAlgorithmType hmacAlgorithmType)
        {
            _hmacAlgorithmType = hmacAlgorithmType;
        }

        public HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, SeekOptions seekOptions, byte[] key = null)
        {
            if (bytesToComputeHMAC == null || bytesToComputeHMAC.Length <= 0)
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_InputRequired
                };
            }

            if (key == null || key.Length == 0)
            {
                key = CryptographyCommon.GenerateRandomBytes(HMACUtil.HMACLengthMapper[_hmacAlgorithmType] / 8);
            }

            HMACResult result = null;

            try
            {
                using (var hmac = (System.Security.Cryptography.HMAC)CryptoConfig.CreateFromName(_hmacAlgorithmType.ToString()))
                {
                    hmac.Key = key;
                    var count = (seekOptions.Count == 0 ? bytesToComputeHMAC.Length : seekOptions.Count);

                    var hash = hmac.ComputeHash(bytesToComputeHMAC, seekOptions.Offset, count);

                    result = new HMACResult()
                    {
                        Success = true,
                        Message = MessageStrings.HMAC_ComputeSuccess,
                        HashBytes = hash,
                        HashString = Hexadecimal.ToHexadecimalString(hash),
                        Key = key,
                        HMACAlgorithmType = _hmacAlgorithmType
                    };
                }
            }
            catch (Exception ex)
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }

            return result;
        }

        public HMACResult ComputeHMAC(string stringToComputeHMAC, SeekOptions seekOptions, byte[] key = null)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHMAC))
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = MessageStrings.HMAC_InputRequired
                };
            }

            var stringToComputeHMACBytes = System.Text.Encoding.UTF8.GetBytes(stringToComputeHMAC);

            return ComputeHMAC(stringToComputeHMACBytes, seekOptions, key);
        }

        public HMACResult ComputeFileHMAC(string filePathToComputeHMAC, LongSeekOptions seekOptions, byte[] key = null)
        {
            if (!File.Exists(filePathToComputeHMAC))
            {
                return new HMACResult()
                {
                    Success = false,
                    Message = $"{MessageStrings.Common_FileNotFound} \"{filePathToComputeHMAC}\"."
                };
            }

            if (key == null || key.Length == 0)
            {
                key = CryptographyCommon.GenerateRandomBytes(HMACUtil.HMACLengthMapper[_hmacAlgorithmType] / 8);
            }

            HMACResult result = null;

            try
            {
                byte[] hash = null;

                using (var fStream = new FileStream(filePathToComputeHMAC, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    var count = seekOptions.Count == 0 ? fStream.Length : seekOptions.Count;
                    fStream.Position = seekOptions.Offset;
                    var buffer = new byte[FileReadBufferSize];
                    var amount = (count - seekOptions.Offset);

                    using (var hmac = (System.Security.Cryptography.HMAC)CryptoConfig.CreateFromName(_hmacAlgorithmType.ToString()))
                    {
                        hmac.Key = key;
                        var percentageDone = 0;

                        while (amount > 0)
                        {
                            var bytesRead = fStream.Read(buffer, 0, (int)Math.Min(buffer.Length, amount));

                            if (bytesRead > 0)
                            {
                                amount -= bytesRead;

                                if (amount > 0)
                                {
                                    hmac.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                                }
                                else
                                {
                                    hmac.TransformFinalBlock(buffer, 0, bytesRead);
                                }

                                var tmpPercentageDone = (int)(fStream.Position * 100 / count);

                                if (tmpPercentageDone != percentageDone)
                                {
                                    percentageDone = tmpPercentageDone;

                                    RaiseOnHMACProgressEvent(percentageDone, (percentageDone != 100 ? $"Computing HMAC ({percentageDone}%)..." : $"HMAC computed ({percentageDone}%)."));
                                }
                            }
                            else
                            {
                                throw new InvalidOperationException();
                            }
                        }

                        hash = hmac.Hash;
                    }
                }

                result = new HMACResult()
                {
                    Success = true,
                    Message = MessageStrings.HMAC_ComputeSuccess,
                    HashString = Hexadecimal.ToHexadecimalString(hash),
                    HashBytes = hash,
                    Key = key
                };
            }
            catch (Exception ex)
            {
                result = new HMACResult()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }

            return result;
        }


        public HMACResult VerifyHMAC(byte[] hmacBytes, byte[] bytesToVerifyHMAC, SeekOptions seekOptions, byte[] key)
        {
            var hmacResult = ComputeHMAC(bytesToVerifyHMAC, seekOptions, key);

            if (hmacResult.Success)
            {
                var hashesMatch = hmacResult.HashBytes.SequenceEqual(hmacBytes);

                hmacResult.Success = hashesMatch;
                hmacResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hmacResult;
        }

        public HMACResult VerifyHMAC(string hmacHexString, string stringToVerifyHMAC, SeekOptions seekOptions, byte[] key)
        {
            var hmacBytes = Encoding.Hexadecimal.ToByteArray(hmacHexString);
            var stringToVerifyHMACBytes = System.Text.Encoding.UTF8.GetBytes(stringToVerifyHMAC);

            return VerifyHMAC(hmacBytes, stringToVerifyHMACBytes, seekOptions, key);
        }

        public HMACResult VerifyFileHMAC(string hmacHexString, string filePathToVerifyHMAC, LongSeekOptions seekOptions, byte[] key)
        {
            var hmacBytes = Encoding.Hexadecimal.ToByteArray(hmacHexString);

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

        private void RaiseOnHMACProgressEvent(int percentageDone, string message) =>
            OnHMACProgress?.Invoke(percentageDone, message);
    }
}
