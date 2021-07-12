using CryptographyHelpers.Hash;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;

namespace CryptographyHelpers.Tests.Hash
{
    [TestClass]
    public class HashTests
    {
        private const string PlainTestString = "This is a test string!";
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
        public void ShouldReturnSuccessFalse_InComputeHash_WhenProvidedInvalidInputText(HashCore hashAlgorithm, string invalidInputText)
        {
            HashResult hashResult;
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_InputTextRequired,
            };

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.ComputeHash(invalidInputText);
            }

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidInputFilePath), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InComputeFileHash_WhenProvidedInvalidFilePathToComputeHash(HashCore hashAlgorithm, string invalidInputFilePath)
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
        public void ShouldReturnSuccessFalse_InVerifyHash_WhenProvidedInvalidInputText(HashCore hashAlgorithm, string invalidInputText)
        {
            HashResult hashResult;
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_InputTextRequired,
            };

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.VerifyHash(invalidInputText, Guid.NewGuid().ToString());
            }

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidEncodedInputVerificationHashString), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyHash_WhenProvidedInvalidEncodedInputVerificationHashString(HashCore hashAlgorithm, string invalidEncodedInputVerificationHashString)
        {
            HashResult hashResult;

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.VerifyHash(Guid.NewGuid().ToString(), invalidEncodedInputVerificationHashString);
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
        [DynamicData(nameof(GetHashAlgorithmInputTextOffsetOptionsAndExpectedHashedString), DynamicDataSourceType.Method)]
        public void ShouldComputeHashFromStringSuccesfully_WithAndWithoutOffsetOptions(HashCore hashAlgorithm, string inputText, OffsetOptions offsetOptions, string expectedHashString)
        {
            HashResult computeHashResult;

            using (hashAlgorithm)
            {
                computeHashResult = hashAlgorithm.ComputeHash(inputText, offsetOptions);
            }

            computeHashResult.Success.Should().BeTrue();
            computeHashResult.HashString.Should().Be(expectedHashString);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmInputTextOffsetOptionsAndExpectedHashedString), DynamicDataSourceType.Method)]
        public void ShouldVerifyHashFromStringSuccesfully_WithAndWithoutOffsetOptions(HashCore hashAlgorithm, string inputText, OffsetOptions offsetOptions, string expectedHashString)
        {
            HashResult verificationHashResult;

            using (hashAlgorithm)
            {
                verificationHashResult = hashAlgorithm.VerifyHash(inputText, expectedHashString, offsetOptions);
            }

            verificationHashResult.Success.Should().BeTrue();
            verificationHashResult.Message.Should().Be(MessageStrings.Hash_Match);
            verificationHashResult.HashString.Should().Be(expectedHashString);
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
                new object[]{ new MD5(), "" },
                new object[]{ new MD5(), "   " },

                new object[]{ new SHA1(), null },
                new object[]{ new SHA1(), "" },
                new object[]{ new SHA1(), "   " },

                new object[]{ new SHA256(), null },
                new object[]{ new SHA256(), "" },
                new object[]{ new SHA256(), "   " },

                new object[]{ new SHA384(), null },
                new object[]{ new SHA384(), "" },
                new object[]{ new SHA384(), "   " },

                new object[]{ new SHA512(), null },
                new object[]{ new SHA512(), "" },
                new object[]{ new SHA512(), "   " },
            };

        private static IEnumerable<object[]> GetHashAlgorithmAndInvalidInputFilePath()
        {
            var invalidFilePath = $@"Z:\{Guid.NewGuid()}\{Guid.NewGuid()}.txt";

            return new List<object[]>()
            {
                new object[]{ new MD5(), null },
                new object[]{ new MD5(), "" },
                new object[]{ new MD5(), "   " },
                new object[]{ new MD5(), invalidFilePath },

                new object[]{ new SHA1(), null },
                new object[]{ new SHA1(), "" },
                new object[]{ new SHA1(), "   " },
                new object[]{ new SHA1(), invalidFilePath },

                new object[]{ new SHA256(), null },
                new object[]{ new SHA256(), "" },
                new object[]{ new SHA256(), "   " },
                new object[]{ new SHA256(), invalidFilePath },

                new object[]{ new SHA384(), null },
                new object[]{ new SHA384(), "" },
                new object[]{ new SHA384(), "   " },
                new object[]{ new SHA384(), invalidFilePath },

                new object[]{ new SHA512(), null },
                new object[]{ new SHA512(), "" },
                new object[]{ new SHA512(), "   " },
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
                new object[]{ new MD5(), "" },
                new object[]{ new MD5(), "   " },
                new object[]{ new MD5(), invalidHexadecimalEncodedString },
                new object[]{ new MD5(), invalidBase64EncodedString },

                new object[]{ new SHA1(), null },
                new object[]{ new SHA1(), "" },
                new object[]{ new SHA1(), "   " },
                new object[]{ new SHA1(), invalidHexadecimalEncodedString },
                new object[]{ new SHA1(), invalidBase64EncodedString },

                new object[]{ new SHA256(), null },
                new object[]{ new SHA256(), "" },
                new object[]{ new SHA256(), "   " },
                new object[]{ new SHA256(), invalidHexadecimalEncodedString },
                new object[]{ new SHA256(), invalidBase64EncodedString },

                new object[]{ new SHA384(), null },
                new object[]{ new SHA384(), "" },
                new object[]{ new SHA384(), "   " },
                new object[]{ new SHA384(), invalidHexadecimalEncodedString },
                new object[]{ new SHA384(), invalidBase64EncodedString },

                new object[]{ new SHA512(), null },
                new object[]{ new SHA512(), "" },
                new object[]{ new SHA512(), "   " },
                new object[]{ new SHA512(), invalidHexadecimalEncodedString },
                new object[]{ new SHA512(), invalidBase64EncodedString },
            };
        }

        private static IEnumerable<object[]> GetHashAlgorithmInputTextOffsetOptionsAndExpectedHashedString()
        {
            var additionalDataLength = 10;
            var inputText = PlainTestString;
            var inputTextWithAdditionalData = $"{new string('a', additionalDataLength)}{inputText}{new string('z', additionalDataLength)}";

            var testStringHexEncodedMd5Hash = "ACB5A0BB8B17EADA5ACD8CED350BB856";
            var testStringBase64EncodedMd5Hash = "rLWgu4sX6tpazYztNQu4Vg==";

            var testStringHexEncodedSha1Hash = "923E2FEF491AFD5A92097C0AAE64AC322FF8DBBC";
            var testStringBase64EncodedSha1Hash = "kj4v70ka/VqSCXwKrmSsMi/427w=";

            var testStringHexEncodedSha256Hash = "31F83B0A652333BB8CA3644D4EC8BAAB2CC7B5AB9BAC5FC72986E47B591F0705";
            var testStringBase64EncodedSha256Hash = "Mfg7CmUjM7uMo2RNTsi6qyzHtaubrF/HKYbke1kfBwU=";

            var testStringHexEncodedSha384Hash = "2E4C0C89E1E1B6D762477B3A0F61CE4D50F130166CFA4E12F811E7B778199C553AC83F90ED7F5868E1C5FE8DD6C55165";
            var testStringBase64EncodedSha384Hash = "LkwMieHhttdiR3s6D2HOTVDxMBZs+k4S+BHnt3gZnFU6yD+Q7X9YaOHF/o3WxVFl";

            var testStringHexEncodedSha512Hash = "C2DC10A16CB105F4D68CB180024ECB93DA298A2BB9DCDBD82A24F6676AA6F129A899BDB99467F4DDF958767696BEC5D0AC3D5C938B9DB798439EDA573F0985FF";
            var testStringBase64EncodedSha512Hash = "wtwQoWyxBfTWjLGAAk7Lk9opiiu53NvYKiT2Z2qm8Smomb25lGf03flYdnaWvsXQrD1ck4udt5hDntpXPwmF/w==";


            return new List<object[]>()
            {
                new object[]{ new MD5(EncodingType.Hexadecimal), inputText, new OffsetOptions(), testStringHexEncodedMd5Hash },
                new object[]{ new MD5(EncodingType.Hexadecimal), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), testStringHexEncodedMd5Hash },
                new object[]{ new MD5(EncodingType.Base64), inputText, new OffsetOptions(), testStringBase64EncodedMd5Hash },
                new object[]{ new MD5(EncodingType.Base64), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), testStringBase64EncodedMd5Hash },

                new object[]{ new SHA1(EncodingType.Hexadecimal), inputText, new OffsetOptions(), testStringHexEncodedSha1Hash },
                new object[]{ new SHA1(EncodingType.Hexadecimal), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), testStringHexEncodedSha1Hash },
                new object[]{ new SHA1(EncodingType.Base64), inputText, new OffsetOptions(), testStringBase64EncodedSha1Hash },
                new object[]{ new SHA1(EncodingType.Base64), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), testStringBase64EncodedSha1Hash },

                new object[]{ new SHA256(EncodingType.Hexadecimal), inputText, new OffsetOptions(), testStringHexEncodedSha256Hash },
                new object[]{ new SHA256(EncodingType.Hexadecimal), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), testStringHexEncodedSha256Hash },
                new object[]{ new SHA256(EncodingType.Base64), inputText, new OffsetOptions(), testStringBase64EncodedSha256Hash },
                new object[]{ new SHA256(EncodingType.Base64), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), testStringBase64EncodedSha256Hash },

                new object[]{ new SHA384(EncodingType.Hexadecimal), inputText, new OffsetOptions(), testStringHexEncodedSha384Hash },
                new object[]{ new SHA384(EncodingType.Hexadecimal), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), testStringHexEncodedSha384Hash },
                new object[]{ new SHA384(EncodingType.Base64), inputText, new OffsetOptions(), testStringBase64EncodedSha384Hash },
                new object[]{ new SHA384(EncodingType.Base64), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), testStringBase64EncodedSha384Hash },

                new object[]{ new SHA512(EncodingType.Hexadecimal), inputText, new OffsetOptions(), testStringHexEncodedSha512Hash },
                new object[]{ new SHA512(EncodingType.Hexadecimal), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), testStringHexEncodedSha512Hash },
                new object[]{ new SHA512(EncodingType.Base64), inputText, new OffsetOptions(), testStringBase64EncodedSha512Hash },
                new object[]{ new SHA512(EncodingType.Base64), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), testStringBase64EncodedSha512Hash },
            };
        }
    }
}