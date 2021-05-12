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
    public class HashBase : IHashBase
    {
        public event OnHashProgressHandler OnHashProgress;

        public GenericHashResult ComputeHash(
            byte[] bytesToComputeHash,
            HashAlgorithmType hashAlgorithmType,
            IntPositionOptions positionOptions,
            HexadecimalEncodingOptions hexadecimalOutputEncodingOptions)
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
                    var count = (positionOptions.Count == 0 ? bytesToComputeHash.Length : positionOptions.Count);
                    var hash = hashAlg.ComputeHash(bytesToComputeHash, positionOptions.Offset, count);

                    result = new GenericHashResult()
                    {
                        Success = true,
                        Message = MessageStrings.Hash_ComputeSuccess,
                        HashAlgorithmType = hashAlgorithmType,
                        HashBytes = hash,
                        HashString = ServiceLocator.Instance.GetService<IHexadecimal>().ToHexadecimalString(hash, hexadecimalOutputEncodingOptions),
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

        public GenericHashResult ComputeHash(
            string stringToComputeHash,
            HashAlgorithmType hashAlgorithmType,
            IntPositionOptions positionOptions,
            HexadecimalEncodingOptions hexadecimalOutputEncodingOptions)
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

            return ComputeHash(stringToComputeHashBytes, hashAlgorithmType, positionOptions, hexadecimalOutputEncodingOptions);
        }

        public GenericHashResult ComputeFileHash(
            string fileToComputeHash,
            HashAlgorithmType hashAlgorithmType,
            LongPositionOptions positionOptions,
            HexadecimalEncodingOptions hexadecimalOutputEncodingOptions)
        {
            if (!File.Exists(fileToComputeHash))
            {
                return new GenericHashResult()
                {
                    Success = false,
                    Message = $"{MessageStrings.File_PathNotFound} \"{fileToComputeHash}\".",
                };
            }

            GenericHashResult result;
            var hashAlg = (HashAlgorithm)CryptoConfig.CreateFromName(hashAlgorithmType.ToString());

            try
            {
                byte[] hash = null;

                using (var fStream = new FileStream(fileToComputeHash, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    var count = (positionOptions.Count == 0 ? fStream.Length : positionOptions.Count);
                    fStream.Position = positionOptions.Offset;
                    var buffer = new byte[(1024 * 4)];
                    var amount = (count - positionOptions.Offset);

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
                    HashString = ServiceLocator.Instance.GetService<IHexadecimal>().ToHexadecimalString(hash, hexadecimalOutputEncodingOptions),
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


        public GenericHashResult VerifyHash(
            byte[] hashBytes,
            byte[] bytesToVerifyHash,
            HashAlgorithmType hashAlgorithmType,
            IntPositionOptions positionOptions)
        {
            HexadecimalEncodingOptions hexadecimalEncodingOptions = new(includeHexIndicatorPrefix: false, outputCharacterCasing: CharacterCasing.Upper);
            var hashResult = ComputeHash(bytesToVerifyHash, hashAlgorithmType, positionOptions, hexadecimalEncodingOptions);

            if (hashResult.Success)
            {
                var hashesMatch = hashResult.HashBytes.SequenceEqual(hashBytes);

                hashResult.Success = hashesMatch;
                hashResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hashResult;
        }

        public GenericHashResult VerifyHash(
            string hashHexadecimalString,
            string stringToVerifyHash,
            HashAlgorithmType hashAlgorithmType,
            IntPositionOptions positionOptions)
        {
            var hashBytes = ServiceLocator.Instance.GetService<IHexadecimal>().ToByteArray(hashHexadecimalString);
            var stringToVerifyHashBytes = StringUtil.GetUTF8BytesFromString(stringToVerifyHash);

            return VerifyHash(stringToVerifyHashBytes, hashBytes, hashAlgorithmType, positionOptions);
        }

        public GenericHashResult VerifyFileHash(
            string hashHexadecimalString,
            string fileToVerifyHash,
            HashAlgorithmType hashAlgorithmType,
            LongPositionOptions positionOptions)
        {
            var hashBytes = ServiceLocator.Instance.GetService<IHexadecimal>().ToByteArray(hashHexadecimalString);

            return VerifyFileHash(hashBytes, fileToVerifyHash, hashAlgorithmType, positionOptions);
        }

        public GenericHashResult VerifyFileHash(
            byte[] hashBytes,
            string fileToVerifyHash,
            HashAlgorithmType hashAlgorithmType,
            LongPositionOptions positionOptions)
        {
            HexadecimalEncodingOptions hexadecimalEncodingOptions = new(includeHexIndicatorPrefix: false, outputCharacterCasing: CharacterCasing.Upper);
            var hashResult = ComputeFileHash(fileToVerifyHash, hashAlgorithmType, positionOptions, hexadecimalEncodingOptions);

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