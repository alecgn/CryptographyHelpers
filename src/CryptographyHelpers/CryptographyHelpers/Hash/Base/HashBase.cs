using CryptographyHelpers.Encoding;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Util;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CryptographyHelpers.Hash
{
    public class HashBase
    {
        public event OnHashProgressHandler OnHashProgress;

        public GenericHashResult ComputeHash(HashAlgorithmType hashAlgorithmType, byte[] bytesToComputeHash, int offset = 0, int count = 0)
        {
            if (bytesToComputeHash is null || bytesToComputeHash.Length <= 0)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputRequired,
                };
            }

            GenericHashResult result;

            try
            {
                var hashAlg = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlgorithmType.ToString());

                using (hashAlg)
                {
                    count = (count == 0 ? bytesToComputeHash.Length : count);

                    var hash = hashAlg.ComputeHash(bytesToComputeHash, offset, count);

                    result = new GenericHashResult()
                    {
                        Success = true,
                        Message = MessageStrings.Hash_ComputeSuccess,
                        HashAlgorithmType = hashAlgorithmType,
                        HashBytes = hash,
                        HashString = ServiceLocator.Instance.GetService<IHexadecimal>().ToHexadecimalString(hash),
                    };
                }
            }
            catch (Exception ex)
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = ex.ToString()
                };
            }

            return result;
        }

        public GenericHashResult ComputeHash(HashAlgorithmType hashAlgorithmType, string stringToComputeHash, int offset = 0, int count = 0)
        {
            if (string.IsNullOrWhiteSpace(stringToComputeHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = MessageStrings.Hash_InputRequired,
                };
            }

            var stringToComputeHashBytes = StringUtil.GetUTF8BytesFromString(stringToComputeHash);

            return ComputeHash(hashAlgorithmType, stringToComputeHashBytes, offset, count);
        }

        public GenericHashResult ComputeFileHash(HashAlgorithmType hashAlgorithmType, string filePathToComputeHash, long offset = 0, long count = 0)
        {
            if (!File.Exists(filePathToComputeHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = $"{MessageStrings.File_PathNotFound} \"{filePathToComputeHash}\".",
                };
            }

            GenericHashResult result;
            var hashAlg = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlgorithmType.ToString());

            try
            {
                byte[] hash = null;

                using (var fStream = new FileStream(filePathToComputeHash, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    count = (count == 0 ? fStream.Length : count);
                    fStream.Position = offset;
                    var buffer = new byte[(1024 * 4)];
                    var amount = (count - offset);

                    using (hashAlg)
                    {
                        var percentageDone = 0;

                        while (amount > 0)
                        {
                            var bytesRead = fStream.Read(buffer, 0, (int)Math.Min(buffer.Length, amount));

                            if (bytesRead > 0)
                            {
                                amount -= bytesRead;

                                if (amount > 0)
                                {
                                    hashAlg.TransformBlock(buffer, 0, bytesRead, buffer, 0);
                                }
                                else
                                {
                                    hashAlg.TransformFinalBlock(buffer, 0, bytesRead);
                                }

                                var tmpPercentageDone = (int)(fStream.Position * 100 / count);

                                if (tmpPercentageDone != percentageDone)
                                {
                                    percentageDone = tmpPercentageDone;

                                    RaiseOnHashProgress(percentageDone, (percentageDone != 100 ? $"Computing hash ({percentageDone}%)..." : $"Hash computed ({percentageDone}%)."));
                                }
                            }
                            else
                            {
                                throw new InvalidOperationException();
                            }
                        }

                        hash = hashAlg.Hash;
                    }
                }

                result = new GenericHashResult()
                {
                    Success = true,
                    Message = MessageStrings.Hash_ComputeSuccess,
                    HashAlgorithmType = hashAlgorithmType,
                    HashString = ServiceLocator.Instance.GetService<IHexadecimal>().ToHexadecimalString(hash),
                    HashBytes = hash,
                };
            }
            catch (Exception ex)
            {
                result = new GenericHashResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }

            return result;
        }


        public GenericHashResult VerifyHash(HashAlgorithmType hashAlgorithmType, byte[] hashBytes, byte[] bytesToVerifyHash, int offset = 0, int count = 0)
        {
            var hashResult = ComputeHash(hashAlgorithmType, bytesToVerifyHash, offset, count);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(hashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }

        public GenericHashResult VerifyHash(HashAlgorithmType hashAlgorithmType, string hashHexadecimalString, string stringToVerifyHash, int offset = 0, int count = 0)
        {
            var hashBytes = ServiceLocator.Instance.GetService<IHexadecimal>().ToByteArray(hashHexadecimalString);
            var stringToVerifyHashBytes = StringUtil.GetUTF8BytesFromString(stringToVerifyHash);

            return VerifyHash(hashAlgorithmType, hashBytes, stringToVerifyHashBytes, offset, count);
        }

        public GenericHashResult VerifyFileHash(HashAlgorithmType hashAlgorithmType, string hashHexadecimalString, string filePathToVerifyHash, long offset = 0, long count = 0)
        {
            var hashBytes = ServiceLocator.Instance.GetService<IHexadecimal>().ToByteArray(hashHexadecimalString);

            return VerifyFileHash(hashAlgorithmType, hashBytes, filePathToVerifyHash, offset, count);
        }

        public GenericHashResult VerifyFileHash(HashAlgorithmType hashAlgorithmType, byte[] hashBytes, string filePathToVerifyHash, long offset = 0, long count = 0)
        {
            var hashResult = ComputeFileHash(hashAlgorithmType, filePathToVerifyHash, offset, count);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(hashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }

        private void RaiseOnHashProgress(int percentageDone, string message)
        {
            OnHashProgress?.Invoke(percentageDone, message);
        }
    }
}
