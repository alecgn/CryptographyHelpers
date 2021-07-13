using CryptographyHelpers.Hash;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;

namespace CryptographyHelpers.Tests.Hash
{
    [TestClass]
    public class HashTests
    {
        private const string PlainTestString = "This is a test string!";
        private const string TestStringMd5HashHexEncoded = "ACB5A0BB8B17EADA5ACD8CED350BB856";
        private const string TestStringMd5HashBase64Encoded = "rLWgu4sX6tpazYztNQu4Vg==";
        private const string TestStringSha1HashHexEncoded = "923E2FEF491AFD5A92097C0AAE64AC322FF8DBBC";
        private const string TestStringSha1HashBase64Encoded = "kj4v70ka/VqSCXwKrmSsMi/427w=";
        private const string TestStringSha256HashHexEncoded = "31F83B0A652333BB8CA3644D4EC8BAAB2CC7B5AB9BAC5FC72986E47B591F0705";
        private const string TestStringSha256HashBase64Encoded = "Mfg7CmUjM7uMo2RNTsi6qyzHtaubrF/HKYbke1kfBwU=";
        private const string TestStringSha384HashHexEncoded = "2E4C0C89E1E1B6D762477B3A0F61CE4D50F130166CFA4E12F811E7B778199C553AC83F90ED7F5868E1C5FE8DD6C55165";
        private const string TestStringSha384HashBase64Encoded = "LkwMieHhttdiR3s6D2HOTVDxMBZs+k4S+BHnt3gZnFU6yD+Q7X9YaOHF/o3WxVFl";
        private const string TestStringSha512HashHexEncoded = "C2DC10A16CB105F4D68CB180024ECB93DA298A2BB9DCDBD82A24F6676AA6F129A899BDB99467F4DDF958767696BEC5D0AC3D5C938B9DB798439EDA573F0985FF";
        private const string TestStringSha512HashBase64Encoded = "wtwQoWyxBfTWjLGAAk7Lk9opiiu53NvYKiT2Z2qm8Smomb25lGf03flYdnaWvsXQrD1ck4udt5hDntpXPwmF/w==";


        private const string WhiteSpaceString = " ";

        private static readonly IBase64 _base64Encoder = InternalServiceLocator.Instance.GetService<IBase64>();
        private static readonly IHexadecimal _hexadecimalEncoder = InternalServiceLocator.Instance.GetService<IHexadecimal>();

        
        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InComputeHash_WhenProvidedInvalidInputData(HashCore hashAlgorithm, byte[] invalidInputData)
        {
            HashResult hashResult;
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_InputBytesRequired,
            };

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.ComputeHash(invalidInputData);
            }

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidInputText), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InComputeTextHash_WhenProvidedInvalidInputText(HashCore hashAlgorithm, string invalidInputText)
        {
            HashResult hashResult;
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_InputTextRequired,
            };

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.ComputeTextHash(invalidInputText);
            }

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidInputFilePath), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InComputeFileHash_WhenProvidedInvalidInputFilePath(HashCore hashAlgorithm, string invalidInputFilePath)
        {
            HashResult hashResult;
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = $@"{MessageStrings.File_PathNotFound} ""{invalidInputFilePath}"".",
            };

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.ComputeFileHash(invalidInputFilePath);
            }

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyHash_WhenProvidedInvalidInputVerificationHash(HashCore hashAlgorithm, byte[] invalidInputVerificationHash)
        {
            HashResult hashResult;
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_VerificationHashBytesRequired,
            };

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.VerifyHash(Array.Empty<byte>(), invalidInputVerificationHash);
            }

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidInputText), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyTextHash_WhenProvidedInvalidInputText(HashCore hashAlgorithm, string invalidInputText)
        {
            HashResult hashResult;
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_InputTextRequired,
            };

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.VerifyTextHash(invalidInputText, Guid.NewGuid().ToString());
            }

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidEncodedInputVerificationHashString), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyTextHash_WhenProvidedInvalidEncodedInputVerificationHashString(HashCore hashAlgorithm, string invalidEncodedInputVerificationHashString)
        {
            HashResult hashResult;

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.VerifyTextHash(Guid.NewGuid().ToString(), invalidEncodedInputVerificationHashString);
            }

            hashResult.Success.Should().BeFalse();
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyFileHash_WhenProvidedInvalidInputVerificationHash(HashCore hashAlgorithm, byte[] invalidInputVerificationHash)
        {
            HashResult hashResult;
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_VerificationHashBytesRequired,
            };

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.VerifyFileHash(Guid.NewGuid().ToString(), invalidInputVerificationHash);
            }

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidEncodedInputVerificationHashString), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyFileHash_WhenProvidedInvalidEncodedInputVerificationHashString(HashCore hashAlgorithm, string invalidEncodedInputVerificationHashString)
        {
            HashResult hashResult;

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.VerifyFileHash(Guid.NewGuid().ToString(), invalidEncodedInputVerificationHashString);
            }

            hashResult.Success.Should().BeFalse();
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmInputDataOffsetOptionsAndExpectedHashString), DynamicDataSourceType.Method)]
        public void ShouldComputeHashSuccesfully_InComputeHash_WithAndWithoutOffsetOptions(HashCore hashAlgorithm, byte[] inputData, OffsetOptions offsetOptions, string expectedHashString)
        {
            HashResult computeHashResult;

            using (hashAlgorithm)
            {
                computeHashResult = hashAlgorithm.ComputeHash(inputData, offsetOptions);
            }

            computeHashResult.Success.Should().BeTrue();
            computeHashResult.HashString.Should().Be(expectedHashString);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmInputTextOffsetOptionsAndVerificationHashString), DynamicDataSourceType.Method)]
        public void ShouldComputeHashFromTextSuccesfully_InComputeTextHash_WithAndWithoutOffsetOptions(HashCore hashAlgorithm, string inputText, OffsetOptions offsetOptions, string expectedHashString)
        {
            HashResult computeHashResult;

            using (hashAlgorithm)
            {
                computeHashResult = hashAlgorithm.ComputeTextHash(inputText, offsetOptions);
            }

            computeHashResult.Success.Should().BeTrue();
            computeHashResult.HashString.Should().Be(expectedHashString);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmFilePathOffsetOptionsAndExpectedHashString), DynamicDataSourceType.Method)]
        public void ShouldComputeHashFromFileSuccesfully_InComputeFileHash_WithAndWithoutOffsetOptions(HashCore hashAlgorithm, string filePath, LongOffsetOptions offsetOptions, string expectedHashString)
        {
            HashResult computeHashResult;

            using (hashAlgorithm)
            {
                computeHashResult = hashAlgorithm.ComputeFileHash(filePath, offsetOptions);
            }

            computeHashResult.Success.Should().BeTrue();
            computeHashResult.HashString.Should().Be(expectedHashString);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmInputDataOffsetOptionsAndExpectedVerificationHash), DynamicDataSourceType.Method)]
        public void ShouldVerifyHashSuccesfully_InVerifyHash_WithAndWithoutOffsetOptions(HashCore hashAlgorithm, byte[] inputData, OffsetOptions offsetOptions, byte[] verificationHash)
        {
            HashResult verificationHashResult;

            using (hashAlgorithm)
            {
                verificationHashResult = hashAlgorithm.VerifyHash(inputData, verificationHash, offsetOptions);
            }

            verificationHashResult.Success.Should().BeTrue();
            verificationHashResult.Message.Should().Be(MessageStrings.Hash_Match);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmInputTextOffsetOptionsAndVerificationHashString), DynamicDataSourceType.Method)]
        public void ShouldVerifyHashFromTextSuccesfully_InVerifyTextHash_WithAndWithoutOffsetOptions(HashCore hashAlgorithm, string inputText, OffsetOptions offsetOptions, string verificationHashString)
        {
            HashResult verificationHashResult;

            using (hashAlgorithm)
            {
                verificationHashResult = hashAlgorithm.VerifyTextHash(inputText, verificationHashString, offsetOptions);
            }

            verificationHashResult.Success.Should().BeTrue();
            verificationHashResult.Message.Should().Be(MessageStrings.Hash_Match);
            verificationHashResult.HashString.Should().Be(verificationHashString);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmFilePathOffsetOptionsAndExpectedHashString), DynamicDataSourceType.Method)]
        public void ShouldVerifyHashFromFileSuccesfully_InVerifyFileHash_WithAndWithoutOffsetOptions(HashCore hashAlgorithm, string filePath, LongOffsetOptions offsetOptions, string verificationHashString)
        {
            HashResult verificationHashResult;

            using (hashAlgorithm)
            {
                verificationHashResult = hashAlgorithm.VerifyFileHash(filePath, verificationHashString, offsetOptions);
            }

            verificationHashResult.Success.Should().BeTrue();
            verificationHashResult.Message.Should().Be(MessageStrings.Hash_Match);
            verificationHashResult.HashString.Should().Be(verificationHashString);
        }


        private static IEnumerable<object[]> GetHashAlgorithmAndInvalidInputData() =>
            new List<object[]>()
            {
                new object[]{ new MD5(), null },
                new object[]{ new MD5(), Array.Empty<byte>() },

                new object[]{ new SHA1(), null },
                new object[]{ new SHA1(), Array.Empty<byte>() },

                new object[]{ new SHA256(), null },
                new object[]{ new SHA256(), Array.Empty<byte>() },

                new object[]{ new SHA384(), null },
                new object[]{ new SHA384(), Array.Empty<byte>() },

                new object[]{ new SHA512(), null },
                new object[]{ new SHA512(), Array.Empty<byte>() },
            };

        private static IEnumerable<object[]> GetHashAlgorithmAndInvalidInputText() =>
            new List<object[]>()
            {
                new object[]{ new MD5(), null },
                new object[]{ new MD5(), string.Empty },
                new object[]{ new MD5(), WhiteSpaceString },

                new object[]{ new SHA1(), null },
                new object[]{ new SHA1(), string.Empty },
                new object[]{ new SHA1(), WhiteSpaceString },

                new object[]{ new SHA256(), null },
                new object[]{ new SHA256(), string.Empty },
                new object[]{ new SHA256(), WhiteSpaceString },

                new object[]{ new SHA384(), null },
                new object[]{ new SHA384(), string.Empty },
                new object[]{ new SHA384(), WhiteSpaceString },

                new object[]{ new SHA512(), null },
                new object[]{ new SHA512(), string.Empty },
                new object[]{ new SHA512(), WhiteSpaceString },
            };

        private static IEnumerable<object[]> GetHashAlgorithmAndInvalidInputFilePath()
        {
            var invalidFilePath = $@"Z:\{Guid.NewGuid()}\{Guid.NewGuid()}.txt";

            return new List<object[]>()
            {
                new object[]{ new MD5(), null },
                new object[]{ new MD5(), string.Empty },
                new object[]{ new MD5(), WhiteSpaceString },
                new object[]{ new MD5(), invalidFilePath },

                new object[]{ new SHA1(), null },
                new object[]{ new SHA1(), string.Empty },
                new object[]{ new SHA1(), WhiteSpaceString },
                new object[]{ new SHA1(), invalidFilePath },

                new object[]{ new SHA256(), null },
                new object[]{ new SHA256(), string.Empty },
                new object[]{ new SHA256(), WhiteSpaceString },
                new object[]{ new SHA256(), invalidFilePath },

                new object[]{ new SHA384(), null },
                new object[]{ new SHA384(), string.Empty },
                new object[]{ new SHA384(), WhiteSpaceString },
                new object[]{ new SHA384(), invalidFilePath },

                new object[]{ new SHA512(), null },
                new object[]{ new SHA512(), string.Empty },
                new object[]{ new SHA512(), WhiteSpaceString },
                new object[]{ new SHA512(), invalidFilePath },
            };
        }

        private static IEnumerable<object> GetHashAlgorithmAndInvalidEncodedInputVerificationHashString()
        {
            var randomBytes = CryptographyUtils.GenerateRandomBytes(10);
            var invalidHexadecimalEncodedString = _hexadecimalEncoder.EncodeToString(randomBytes).Substring(1);
            var invalidBase64EncodedString = _base64Encoder.EncodeToString(randomBytes).Substring(1);

            return new List<object[]>()
            {
                new object[]{ new MD5(), null },
                new object[]{ new MD5(), string.Empty },
                new object[]{ new MD5(), WhiteSpaceString },
                new object[]{ new MD5(), invalidHexadecimalEncodedString },
                new object[]{ new MD5(), invalidBase64EncodedString },

                new object[]{ new SHA1(), null },
                new object[]{ new SHA1(), string.Empty },
                new object[]{ new SHA1(), WhiteSpaceString },
                new object[]{ new SHA1(), invalidHexadecimalEncodedString },
                new object[]{ new SHA1(), invalidBase64EncodedString },

                new object[]{ new SHA256(), null },
                new object[]{ new SHA256(), string.Empty },
                new object[]{ new SHA256(), WhiteSpaceString },
                new object[]{ new SHA256(), invalidHexadecimalEncodedString },
                new object[]{ new SHA256(), invalidBase64EncodedString },

                new object[]{ new SHA384(), null },
                new object[]{ new SHA384(), string.Empty },
                new object[]{ new SHA384(), WhiteSpaceString },
                new object[]{ new SHA384(), invalidHexadecimalEncodedString },
                new object[]{ new SHA384(), invalidBase64EncodedString },

                new object[]{ new SHA512(), null },
                new object[]{ new SHA512(), string.Empty },
                new object[]{ new SHA512(), WhiteSpaceString },
                new object[]{ new SHA512(), invalidHexadecimalEncodedString },
                new object[]{ new SHA512(), invalidBase64EncodedString },
            };
        }

        private static IEnumerable<object[]> GetHashAlgorithmInputTextOffsetOptionsAndVerificationHashString()
        {
            var additionalDataLength = 10;
            var inputText = PlainTestString;
            var inputTextWithAdditionalData = $"{new string('a', additionalDataLength)}{inputText}{new string('z', additionalDataLength)}";

            return new List<object[]>()
            {
                new object[]{ new MD5(EncodingType.Hexadecimal), inputText, new OffsetOptions(), TestStringMd5HashHexEncoded },
                new object[]{ new MD5(EncodingType.Hexadecimal), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringMd5HashHexEncoded },
                new object[]{ new MD5(EncodingType.Base64), inputText, new OffsetOptions(), TestStringMd5HashBase64Encoded },
                new object[]{ new MD5(EncodingType.Base64), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringMd5HashBase64Encoded },

                new object[]{ new SHA1(EncodingType.Hexadecimal), inputText, new OffsetOptions(), TestStringSha1HashHexEncoded },
                new object[]{ new SHA1(EncodingType.Hexadecimal), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha1HashHexEncoded },
                new object[]{ new SHA1(EncodingType.Base64), inputText, new OffsetOptions(), TestStringSha1HashBase64Encoded },
                new object[]{ new SHA1(EncodingType.Base64), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha1HashBase64Encoded },

                new object[]{ new SHA256(EncodingType.Hexadecimal), inputText, new OffsetOptions(), TestStringSha256HashHexEncoded },
                new object[]{ new SHA256(EncodingType.Hexadecimal), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha256HashHexEncoded },
                new object[]{ new SHA256(EncodingType.Base64), inputText, new OffsetOptions(), TestStringSha256HashBase64Encoded },
                new object[]{ new SHA256(EncodingType.Base64), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha256HashBase64Encoded },

                new object[]{ new SHA384(EncodingType.Hexadecimal), inputText, new OffsetOptions(), TestStringSha384HashHexEncoded },
                new object[]{ new SHA384(EncodingType.Hexadecimal), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha384HashHexEncoded },
                new object[]{ new SHA384(EncodingType.Base64), inputText, new OffsetOptions(), TestStringSha384HashBase64Encoded },
                new object[]{ new SHA384(EncodingType.Base64), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha384HashBase64Encoded },

                new object[]{ new SHA512(EncodingType.Hexadecimal), inputText, new OffsetOptions(), TestStringSha512HashHexEncoded },
                new object[]{ new SHA512(EncodingType.Hexadecimal), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha512HashHexEncoded },
                new object[]{ new SHA512(EncodingType.Base64), inputText, new OffsetOptions(), TestStringSha512HashBase64Encoded },
                new object[]{ new SHA512(EncodingType.Base64), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha512HashBase64Encoded },
            };
        }

        private static IEnumerable<object[]> GetHashAlgorithmInputDataOffsetOptionsAndExpectedHashString()
        {
            var additionalDataLength = 10;
            var inputText = PlainTestString;
            var inputTextBytes = inputText.ToUTF8Bytes();
            var inputTextWithAdditionalData = $"{new string('a', additionalDataLength)}{inputText}{new string('z', additionalDataLength)}";
            var inputTextWithAdditionalDataBytes = inputTextWithAdditionalData.ToUTF8Bytes();


            return new List<object[]>()
            {
                new object[]{ new MD5(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), TestStringMd5HashHexEncoded },
                new object[]{ new MD5(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringMd5HashHexEncoded },
                new object[]{ new MD5(EncodingType.Base64), inputTextBytes, new OffsetOptions(), TestStringMd5HashBase64Encoded },
                new object[]{ new MD5(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringMd5HashBase64Encoded },

                new object[]{ new SHA1(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), TestStringSha1HashHexEncoded },
                new object[]{ new SHA1(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha1HashHexEncoded },
                new object[]{ new SHA1(EncodingType.Base64), inputTextBytes, new OffsetOptions(), TestStringSha1HashBase64Encoded },
                new object[]{ new SHA1(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha1HashBase64Encoded },

                new object[]{ new SHA256(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), TestStringSha256HashHexEncoded },
                new object[]{ new SHA256(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha256HashHexEncoded },
                new object[]{ new SHA256(EncodingType.Base64), inputTextBytes, new OffsetOptions(), TestStringSha256HashBase64Encoded },
                new object[]{ new SHA256(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha256HashBase64Encoded },

                new object[]{ new SHA384(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), TestStringSha384HashHexEncoded },
                new object[]{ new SHA384(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha384HashHexEncoded },
                new object[]{ new SHA384(EncodingType.Base64), inputTextBytes, new OffsetOptions(), TestStringSha384HashBase64Encoded },
                new object[]{ new SHA384(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha384HashBase64Encoded },

                new object[]{ new SHA512(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), TestStringSha512HashHexEncoded },
                new object[]{ new SHA512(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha512HashHexEncoded },
                new object[]{ new SHA512(EncodingType.Base64), inputTextBytes, new OffsetOptions(), TestStringSha512HashBase64Encoded },
                new object[]{ new SHA512(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha512HashBase64Encoded },
            };
        }

        private static IEnumerable<object[]> GetHashAlgorithmFilePathOffsetOptionsAndExpectedHashString()
        {
            var tempFilePath = Path.GetTempFileName();
            File.WriteAllText(tempFilePath, PlainTestString);

            var tempFilePathWithAdditionalData = Path.GetTempFileName();
            var additionalDataLength = 10;
            var textWithAdditionalData = $"{new string('a', additionalDataLength)}{PlainTestString}{new string('z', additionalDataLength)}";
            File.WriteAllText(tempFilePathWithAdditionalData, textWithAdditionalData);

            var expectedStringHexEncodedMd5Hash = "ACB5A0BB8B17EADA5ACD8CED350BB856";
            var expectedStringBase64EncodedMd5Hash = "rLWgu4sX6tpazYztNQu4Vg==";

            var expectedStringHexEncodedSha1Hash = "923E2FEF491AFD5A92097C0AAE64AC322FF8DBBC";
            var expectedStringBase64EncodedSha1Hash = "kj4v70ka/VqSCXwKrmSsMi/427w=";

            var expectedStringHexEncodedSha256Hash = "31F83B0A652333BB8CA3644D4EC8BAAB2CC7B5AB9BAC5FC72986E47B591F0705";
            var expectedStringBase64EncodedSha256Hash = "Mfg7CmUjM7uMo2RNTsi6qyzHtaubrF/HKYbke1kfBwU=";

            var expectedStringHexEncodedSha384Hash = "2E4C0C89E1E1B6D762477B3A0F61CE4D50F130166CFA4E12F811E7B778199C553AC83F90ED7F5868E1C5FE8DD6C55165";
            var expectedStringBase64EncodedSha384Hash = "LkwMieHhttdiR3s6D2HOTVDxMBZs+k4S+BHnt3gZnFU6yD+Q7X9YaOHF/o3WxVFl";

            var expectedStringHexEncodedSha512Hash = "C2DC10A16CB105F4D68CB180024ECB93DA298A2BB9DCDBD82A24F6676AA6F129A899BDB99467F4DDF958767696BEC5D0AC3D5C938B9DB798439EDA573F0985FF";
            var expectedStringBase64EncodedSha512Hash = "wtwQoWyxBfTWjLGAAk7Lk9opiiu53NvYKiT2Z2qm8Smomb25lGf03flYdnaWvsXQrD1ck4udt5hDntpXPwmF/w==";

            return new List<object[]>()
            {
                new object[]{ new MD5(EncodingType.Hexadecimal), tempFilePath, new LongOffsetOptions(), expectedStringHexEncodedMd5Hash },
                new object[]{ new MD5(EncodingType.Hexadecimal), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), expectedStringHexEncodedMd5Hash },
                new object[]{ new MD5(EncodingType.Base64), tempFilePath, new LongOffsetOptions(), expectedStringBase64EncodedMd5Hash },
                new object[]{ new MD5(EncodingType.Base64), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), expectedStringBase64EncodedMd5Hash },

                new object[]{ new SHA1(EncodingType.Hexadecimal), tempFilePath, new LongOffsetOptions(), expectedStringHexEncodedSha1Hash },
                new object[]{ new SHA1(EncodingType.Hexadecimal), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), expectedStringHexEncodedSha1Hash },
                new object[]{ new SHA1(EncodingType.Base64), tempFilePath, new LongOffsetOptions(), expectedStringBase64EncodedSha1Hash },
                new object[]{ new SHA1(EncodingType.Base64), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), expectedStringBase64EncodedSha1Hash },

                new object[]{ new SHA256(EncodingType.Hexadecimal), tempFilePath, new LongOffsetOptions(), expectedStringHexEncodedSha256Hash },
                new object[]{ new SHA256(EncodingType.Hexadecimal), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), expectedStringHexEncodedSha256Hash },
                new object[]{ new SHA256(EncodingType.Base64), tempFilePath, new LongOffsetOptions(), expectedStringBase64EncodedSha256Hash },
                new object[]{ new SHA256(EncodingType.Base64), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), expectedStringBase64EncodedSha256Hash },

                new object[]{ new SHA384(EncodingType.Hexadecimal), tempFilePath, new LongOffsetOptions(), expectedStringHexEncodedSha384Hash },
                new object[]{ new SHA384(EncodingType.Hexadecimal), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), expectedStringHexEncodedSha384Hash },
                new object[]{ new SHA384(EncodingType.Base64), tempFilePath, new LongOffsetOptions(), expectedStringBase64EncodedSha384Hash },
                new object[]{ new SHA384(EncodingType.Base64), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), expectedStringBase64EncodedSha384Hash },

                new object[]{ new SHA512(EncodingType.Hexadecimal), tempFilePath, new LongOffsetOptions(), expectedStringHexEncodedSha512Hash },
                new object[]{ new SHA512(EncodingType.Hexadecimal), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), expectedStringHexEncodedSha512Hash },
                new object[]{ new SHA512(EncodingType.Base64), tempFilePath, new LongOffsetOptions(), expectedStringBase64EncodedSha512Hash },
                new object[]{ new SHA512(EncodingType.Base64), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), expectedStringBase64EncodedSha512Hash },
            };
        }

        private static IEnumerable<object[]> GetHashAlgorithmInputDataOffsetOptionsAndExpectedVerificationHash()
        {
            var additionalDataLength = 10;
            var inputText = PlainTestString;
            var inputTextBytes = inputText.ToUTF8Bytes();
            var inputTextWithAdditionalData = $"{new string('a', additionalDataLength)}{inputText}{new string('z', additionalDataLength)}";
            var inputTextWithAdditionalDataBytes = inputTextWithAdditionalData.ToUTF8Bytes();

            var md5VerificationHashStringHexEncoded = "ACB5A0BB8B17EADA5ACD8CED350BB856";
            var md5VerificationHashFromHexEncodedString = md5VerificationHashStringHexEncoded.ToBytesFromHexadecimalString();
            var md5VerificationHashStringBase64Encoded = "rLWgu4sX6tpazYztNQu4Vg==";
            var md5VerificationHashFromBase64EncodedString = md5VerificationHashStringBase64Encoded.ToBytesFromBase64String();

            var sha1VerificationHashStringHexEncoded = "923E2FEF491AFD5A92097C0AAE64AC322FF8DBBC";
            var sha1VerificationHashFromHexEncodedString = sha1VerificationHashStringHexEncoded.ToBytesFromHexadecimalString();
            var sha1VerificationHashStringBase64Encoded = "kj4v70ka/VqSCXwKrmSsMi/427w=";
            var sha1VerificationHashFromBase64EncodedString = sha1VerificationHashStringBase64Encoded.ToBytesFromBase64String();

            var sha256VerificationHashStringHexEncoded = "31F83B0A652333BB8CA3644D4EC8BAAB2CC7B5AB9BAC5FC72986E47B591F0705";
            var sha256VerificationHashFromHexEncodedString = sha256VerificationHashStringHexEncoded.ToBytesFromHexadecimalString();
            var sha256VerificationHashStringBase64Encoded = "Mfg7CmUjM7uMo2RNTsi6qyzHtaubrF/HKYbke1kfBwU=";
            var sha256VerificationHashFromBase64EncodedString = sha256VerificationHashStringBase64Encoded.ToBytesFromBase64String();

            var sha384VerificationHashStringHexEncoded = "2E4C0C89E1E1B6D762477B3A0F61CE4D50F130166CFA4E12F811E7B778199C553AC83F90ED7F5868E1C5FE8DD6C55165";
            var sha384VerificationHashFromHexEncodedString = sha384VerificationHashStringHexEncoded.ToBytesFromHexadecimalString();
            var sha384VerificationHashStringBase64Encoded = "LkwMieHhttdiR3s6D2HOTVDxMBZs+k4S+BHnt3gZnFU6yD+Q7X9YaOHF/o3WxVFl";
            var sha384VerificationHashFromBase64EncodedString = sha384VerificationHashStringBase64Encoded.ToBytesFromBase64String();

            var sha512VerificationHashStringHexEncoded = "C2DC10A16CB105F4D68CB180024ECB93DA298A2BB9DCDBD82A24F6676AA6F129A899BDB99467F4DDF958767696BEC5D0AC3D5C938B9DB798439EDA573F0985FF";
            var sha512VerificationHashFromHexEncodedString = sha512VerificationHashStringHexEncoded.ToBytesFromHexadecimalString();
            var sha512VerificationHashStringBase64Encoded = "wtwQoWyxBfTWjLGAAk7Lk9opiiu53NvYKiT2Z2qm8Smomb25lGf03flYdnaWvsXQrD1ck4udt5hDntpXPwmF/w==";
            var sha512VerificationHashFromBase64EncodedString = sha512VerificationHashStringBase64Encoded.ToBytesFromBase64String();


            return new List<object[]>()
            {
                new object[]{ new MD5(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), md5VerificationHashFromHexEncodedString },
                new object[]{ new MD5(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), md5VerificationHashFromHexEncodedString },
                new object[]{ new MD5(EncodingType.Base64), inputTextBytes, new OffsetOptions(), md5VerificationHashFromBase64EncodedString },
                new object[]{ new MD5(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), md5VerificationHashFromBase64EncodedString },

                new object[]{ new SHA1(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), sha1VerificationHashFromHexEncodedString },
                new object[]{ new SHA1(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha1VerificationHashFromHexEncodedString },
                new object[]{ new SHA1(EncodingType.Base64), inputTextBytes, new OffsetOptions(), sha1VerificationHashFromBase64EncodedString },
                new object[]{ new SHA1(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha1VerificationHashFromBase64EncodedString },

                new object[]{ new SHA256(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), sha256VerificationHashFromHexEncodedString },
                new object[]{ new SHA256(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha256VerificationHashFromHexEncodedString },
                new object[]{ new SHA256(EncodingType.Base64), inputTextBytes, new OffsetOptions(), sha256VerificationHashFromBase64EncodedString },
                new object[]{ new SHA256(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha256VerificationHashFromBase64EncodedString },

                new object[]{ new SHA384(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), sha384VerificationHashFromHexEncodedString },
                new object[]{ new SHA384(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha384VerificationHashFromHexEncodedString },
                new object[]{ new SHA384(EncodingType.Base64), inputTextBytes, new OffsetOptions(), sha384VerificationHashFromBase64EncodedString },
                new object[]{ new SHA384(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha384VerificationHashFromBase64EncodedString },

                new object[]{ new SHA512(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), sha512VerificationHashFromHexEncodedString },
                new object[]{ new SHA512(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha512VerificationHashFromHexEncodedString },
                new object[]{ new SHA512(EncodingType.Base64), inputTextBytes, new OffsetOptions(), sha512VerificationHashFromBase64EncodedString },
                new object[]{ new SHA512(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha512VerificationHashFromBase64EncodedString },
            };
        }
    }
}