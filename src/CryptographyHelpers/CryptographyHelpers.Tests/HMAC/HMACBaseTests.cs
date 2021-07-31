using CryptographyHelpers.HMAC;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;

namespace CryptographyHelpers.Tests.HMAC
{
    [TestClass]
    public class HMACBaseTests
    {
        private const string WhiteSpaceString = " ";
        private const string PlainTestString = "This is a test string!";
        private const string SecretKey = "secret_key";
        private const string TestStringHmacShaMd5HashHexEncoded = "F692377864BE3A85587D3A93027D1C86";
        private const string TestStringHmacShaMd5HashBase64Encoded = "9pI3eGS+OoVYfTqTAn0chg==";
        //private const string TestStringSha1HashHexEncoded = "923E2FEF491AFD5A92097C0AAE64AC322FF8DBBC";
        //private const string TestStringSha1HashBase64Encoded = "kj4v70ka/VqSCXwKrmSsMi/427w=";
        //private const string TestStringSha256HashHexEncoded = "31F83B0A652333BB8CA3644D4EC8BAAB2CC7B5AB9BAC5FC72986E47B591F0705";
        //private const string TestStringSha256HashBase64Encoded = "Mfg7CmUjM7uMo2RNTsi6qyzHtaubrF/HKYbke1kfBwU=";
        //private const string TestStringSha384HashHexEncoded = "2E4C0C89E1E1B6D762477B3A0F61CE4D50F130166CFA4E12F811E7B778199C553AC83F90ED7F5868E1C5FE8DD6C55165";
        //private const string TestStringSha384HashBase64Encoded = "LkwMieHhttdiR3s6D2HOTVDxMBZs+k4S+BHnt3gZnFU6yD+Q7X9YaOHF/o3WxVFl";
        //private const string TestStringSha512HashHexEncoded = "C2DC10A16CB105F4D68CB180024ECB93DA298A2BB9DCDBD82A24F6676AA6F129A899BDB99467F4DDF958767696BEC5D0AC3D5C938B9DB798439EDA573F0985FF";
        //private const string TestStringSha512HashBase64Encoded = "wtwQoWyxBfTWjLGAAk7Lk9opiiu53NvYKiT2Z2qm8Smomb25lGf03flYdnaWvsXQrD1ck4udt5hDntpXPwmF/w==";

        private static readonly IBase64Encoder _base64Encoder = InternalServiceLocator.Instance.GetService<IBase64Encoder>();
        private static readonly IHexadecimalEncoder _hexadecimalEncoder = InternalServiceLocator.Instance.GetService<IHexadecimalEncoder>();


        [TestMethod]
        [DynamicData(nameof(GetHMACAlgorithmAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InComputeHMAC_WhenProvidedInvalidInputData(HMACBase hmacAlgorithm, byte[] invalidInputData)
        {
            HMACResult hmacResult;
            var expectedHMACResult = new HMACResult()
            {
                Success = false,
                Message = MessageStrings.HMAC_InputBytesRequired,
            };

            using (hmacAlgorithm)
            {
                hmacResult = hmacAlgorithm.ComputeHMAC(invalidInputData);
            }

            hmacResult.Should().BeEquivalentTo(expectedHMACResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHMACAlgorithmAndInvalidInputText), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InComputeTextHMAC_WhenProvidedInvalidInputText(HMACBase hmacAlgorithm, string invalidInputText)
        {
            HMACResult hmacResult;
            var expectedHMACResult = new HMACResult()
            {
                Success = false,
                Message = MessageStrings.HMAC_InputTextRequired,
            };

            using (hmacAlgorithm)
            {
                hmacResult = hmacAlgorithm.ComputeTextHMAC(invalidInputText);
            }

            hmacResult.Should().BeEquivalentTo(expectedHMACResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHMACAlgorithmAndInvalidInputFilePath), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InComputeFileHMAC_WhenProvidedInvalidInputFilePath(HMACBase hmacAlgorithm, string invalidInputFilePath)
        {
            HMACResult hmacResult;
            var expectedHMACResult = new HMACResult()
            {
                Success = false,
                Message = $@"{MessageStrings.File_PathNotFound} ""{invalidInputFilePath}"".",
            };

            using (hmacAlgorithm)
            {
                hmacResult = hmacAlgorithm.ComputeFileHMAC(invalidInputFilePath);
            }

            hmacResult.Should().BeEquivalentTo(expectedHMACResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHMACAlgorithmAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyHMAC_WhenProvidedInvalidInputVerificationHMAC(HMACBase hmacAlgorithm, byte[] invalidInputVerificationHMAC)
        {
            HMACResult hmacResult;
            var expectedHMACResult = new HMACResult()
            {
                Success = false,
                Message = MessageStrings.HMAC_VerificationHMACBytesRequired,
            };

            using (hmacAlgorithm)
            {
                hmacResult = hmacAlgorithm.VerifyHMAC(Array.Empty<byte>(), invalidInputVerificationHMAC);
            }

            hmacResult.Should().BeEquivalentTo(expectedHMACResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHMACAlgorithmAndInvalidInputText), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyTextHMAC_WhenProvidedInvalidInputText(HMACBase hmacAlgorithm, string invalidInputText)
        {
            HMACResult hmacResult;
            var expectedHMACResult = new HMACResult()
            {
                Success = false,
                Message = MessageStrings.HMAC_InputTextRequired,
            };

            using (hmacAlgorithm)
            {
                hmacResult = hmacAlgorithm.VerifyTextHMAC(invalidInputText, Guid.NewGuid().ToString());
            }

            hmacResult.Should().BeEquivalentTo(expectedHMACResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHMACAlgorithmAndInvalidEncodedInputVerificationHMACString), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyTextHMAC_WhenProvidedInvalidEncodedInputVerificationHMACString(HMACBase hmacAlgorithm, string invalidEncodedInputVerificationHMACString)
        {
            HMACResult hmacResult;

            using (hmacAlgorithm)
            {
                hmacResult = hmacAlgorithm.VerifyTextHMAC(Guid.NewGuid().ToString(), invalidEncodedInputVerificationHMACString);
            }

            hmacResult.Success.Should().BeFalse();
        }

        [TestMethod]
        [DynamicData(nameof(GetHMACAlgorithmAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyFileHMAC_WhenProvidedInvalidInputVerificationHMAC(HMACBase hmacAlgorithm, byte[] invalidInputVerificationHMAC)
        {
            HMACResult hmacResult;
            var expectedHMACResult = new HMACResult()
            {
                Success = false,
                Message = MessageStrings.HMAC_VerificationHMACBytesRequired,
            };

            using (hmacAlgorithm)
            {
                hmacResult = hmacAlgorithm.VerifyFileHMAC(Guid.NewGuid().ToString(), invalidInputVerificationHMAC);
            }

            hmacResult.Should().BeEquivalentTo(expectedHMACResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHMACAlgorithmAndInvalidEncodedInputVerificationHMACString), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyFileHMAC_WhenProvidedInvalidEncodedInputVerificationHMACString(HMACBase hmacAlgorithm, string invalidEncodedInputVerificationHMACString)
        {
            HMACResult hmacResult;

            using (hmacAlgorithm)
            {
                hmacResult = hmacAlgorithm.VerifyFileHMAC(Guid.NewGuid().ToString(), invalidEncodedInputVerificationHMACString);
            }

            hmacResult.Success.Should().BeFalse();
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmInputDataOffsetOptionsAndExpectedHashString), DynamicDataSourceType.Method)]
        public void ShouldComputeHMACSuccesfully_InComputeHMAC_WithAndWithoutOffsetOptions(HMACBase hmacAlgorithm, byte[] inputData, OffsetOptions offsetOptions, string expectedHMACString)
        {
            HMACResult computeHMACResult;

            using (hmacAlgorithm)
            {
                computeHMACResult = hmacAlgorithm.ComputeHMAC(inputData, offsetOptions);
            }

            computeHMACResult.Success.Should().BeTrue();
            computeHMACResult.HashString.Should().Be(expectedHMACString);
        }

        [TestMethod]
        [DynamicData(nameof(GetHMACAlgorithmInputTextOffsetOptionsAndVerificationHMACString), DynamicDataSourceType.Method)]
        public void ShouldComputeHMACFromTextSuccesfully_InComputeTextHMAC_WithAndWithoutOffsetOptions(HMACBase hmacAlgorithm, string inputText, OffsetOptions offsetOptions, string expectedHMACString)
        {
            HMACResult computeHMACResult;

            using (hmacAlgorithm)
            {
                computeHMACResult = hmacAlgorithm.ComputeTextHMAC(inputText, offsetOptions);
            }

            computeHMACResult.Success.Should().BeTrue();
            computeHMACResult.HashString.Should().Be(expectedHMACString);
        }

        [TestMethod]
        [DynamicData(nameof(GetHMACAlgorithmFilePathOffsetOptionsAndExpectedHMACString), DynamicDataSourceType.Method)]
        public void ShouldComputeHMACFromFileSuccesfully_InComputeFileHMAC_WithAndWithoutOffsetOptions(HMACBase hmacAlgorithm, string filePath, LongOffsetOptions offsetOptions, string expectedHashString)
        {
            HMACResult computeHMACResult;

            using (hmacAlgorithm)
            {
                computeHMACResult = hmacAlgorithm.ComputeFileHMAC(filePath, offsetOptions);
            }

            computeHMACResult.Success.Should().BeTrue();
            computeHMACResult.HashString.Should().Be(expectedHashString);
        }

        [TestMethod]
        [DynamicData(nameof(GetHMACAlgorithmInputDataOffsetOptionsAndExpectedVerificationHMAC), DynamicDataSourceType.Method)]
        public void ShouldVerifyHMACSuccesfully_InVerifyHMAC_WithAndWithoutOffsetOptions(HMACBase hmacAlgorithm, byte[] inputData, OffsetOptions offsetOptions, byte[] verificationHMAC)
        {
            HMACResult verificationHMACResult;

            using (hmacAlgorithm)
            {
                verificationHMACResult = hmacAlgorithm.VerifyHMAC(inputData, verificationHMAC, offsetOptions);
            }

            verificationHMACResult.Success.Should().BeTrue();
            verificationHMACResult.Message.Should().Be(MessageStrings.HMAC_Match);
        }

        [TestMethod]
        [DynamicData(nameof(GetHMACAlgorithmInputTextOffsetOptionsAndVerificationHMACString), DynamicDataSourceType.Method)]
        public void ShouldVerifyHashFromTextSuccesfully_InVerifyTextHash_WithAndWithoutOffsetOptions(HMACBase hmacAlgorithm, string inputText, OffsetOptions offsetOptions, string verificationHashString)
        {
            HMACResult verificationHashResult;

            using (hmacAlgorithm)
            {
                verificationHashResult = hmacAlgorithm.VerifyTextHMAC(inputText, verificationHashString, offsetOptions);
            }

            verificationHashResult.Success.Should().BeTrue();
            verificationHashResult.Message.Should().Be(MessageStrings.HMAC_Match);
            verificationHashResult.HashString.Should().Be(verificationHashString);
        }

        [TestMethod]
        [DynamicData(nameof(GetHMACAlgorithmFilePathOffsetOptionsAndExpectedHMACString), DynamicDataSourceType.Method)]
        public void ShouldVerifyHMACFromFileSuccesfully_InVerifyFileHMAC_WithAndWithoutOffsetOptions(HMACBase hmacAlgorithm, string filePath, LongOffsetOptions offsetOptions, string verificationHMACString)
        {
            HMACResult verificationHMACResult;

            using (hmacAlgorithm)
            {
                verificationHMACResult = hmacAlgorithm.VerifyFileHMAC(filePath, verificationHMACString, offsetOptions);
            }

            verificationHMACResult.Success.Should().BeTrue();
            verificationHMACResult.Message.Should().Be(MessageStrings.HMAC_Match);
            verificationHMACResult.HashString.Should().Be(verificationHMACString);
        }


        private static IEnumerable<object[]> GetHMACAlgorithmAndInvalidInputData() =>
            new List<object[]>()
            {
                new object[]{ new HMACMD5(), null },
                new object[]{ new HMACMD5(), Array.Empty<byte>() },

                new object[]{ new HMACSHA1(), null },
                new object[]{ new HMACSHA1(), Array.Empty<byte>() },

                new object[]{ new HMACSHA256(), null },
                new object[]{ new HMACSHA256(), Array.Empty<byte>() },

                new object[]{ new HMACSHA384(), null },
                new object[]{ new HMACSHA384(), Array.Empty<byte>() },

                new object[]{ new HMACSHA512(), null },
                new object[]{ new HMACSHA512(), Array.Empty<byte>() },
            };

        private static IEnumerable<object[]> GetHMACAlgorithmAndInvalidInputText() =>
            new List<object[]>()
            {
                new object[]{ new HMACMD5(), null },
                new object[]{ new HMACMD5(), string.Empty },
                new object[]{ new HMACMD5(), WhiteSpaceString },

                new object[]{ new HMACSHA1(), null },
                new object[]{ new HMACSHA1(), string.Empty },
                new object[]{ new HMACSHA1(), WhiteSpaceString },

                new object[]{ new HMACSHA256(), null },
                new object[]{ new HMACSHA256(), string.Empty },
                new object[]{ new HMACSHA256(), WhiteSpaceString },

                new object[]{ new HMACSHA384(), null },
                new object[]{ new HMACSHA384(), string.Empty },
                new object[]{ new HMACSHA384(), WhiteSpaceString },

                new object[]{ new HMACSHA512(), null },
                new object[]{ new HMACSHA512(), string.Empty },
                new object[]{ new HMACSHA512(), WhiteSpaceString },
            };

        private static IEnumerable<object[]> GetHMACAlgorithmAndInvalidInputFilePath()
        {
            var invalidFilePath = $@"Z:\{Guid.NewGuid()}\{Guid.NewGuid()}.txt";

            return new List<object[]>()
            {
                new object[]{ new HMACMD5(), null },
                new object[]{ new HMACMD5(), string.Empty },
                new object[]{ new HMACMD5(), WhiteSpaceString },
                new object[]{ new HMACMD5(), invalidFilePath },

                new object[]{ new HMACSHA1(), null },
                new object[]{ new HMACSHA1(), string.Empty },
                new object[]{ new HMACSHA1(), WhiteSpaceString },
                new object[]{ new HMACSHA1(), invalidFilePath },

                new object[]{ new HMACSHA256(), null },
                new object[]{ new HMACSHA256(), string.Empty },
                new object[]{ new HMACSHA256(), WhiteSpaceString },
                new object[]{ new HMACSHA256(), invalidFilePath },

                new object[]{ new HMACSHA384(), null },
                new object[]{ new HMACSHA384(), string.Empty },
                new object[]{ new HMACSHA384(), WhiteSpaceString },
                new object[]{ new HMACSHA384(), invalidFilePath },

                new object[]{ new HMACSHA512(), null },
                new object[]{ new HMACSHA512(), string.Empty },
                new object[]{ new HMACSHA512(), WhiteSpaceString },
                new object[]{ new HMACSHA512(), invalidFilePath },
            };
        }

        private static IEnumerable<object> GetHMACAlgorithmAndInvalidEncodedInputVerificationHMACString()
        {
            var randomBytes = CryptographyUtils.GenerateRandomBytes(10);
            var invalidHexadecimalEncodedString = _hexadecimalEncoder.EncodeToString(randomBytes)[1..];
            var invalidBase64EncodedString = _base64Encoder.EncodeToString(randomBytes)[1..];

            return new List<object[]>()
            {
                new object[]{ new HMACMD5(), null },
                new object[]{ new HMACMD5(), string.Empty },
                new object[]{ new HMACMD5(), WhiteSpaceString },
                new object[]{ new HMACMD5(), invalidHexadecimalEncodedString },
                new object[]{ new HMACMD5(), invalidBase64EncodedString },

                new object[]{ new HMACSHA1(), null },
                new object[]{ new HMACSHA1(), string.Empty },
                new object[]{ new HMACSHA1(), WhiteSpaceString },
                new object[]{ new HMACSHA1(), invalidHexadecimalEncodedString },
                new object[]{ new HMACSHA1(), invalidBase64EncodedString },

                new object[]{ new HMACSHA256(), null },
                new object[]{ new HMACSHA256(), string.Empty },
                new object[]{ new HMACSHA256(), WhiteSpaceString },
                new object[]{ new HMACSHA256(), invalidHexadecimalEncodedString },
                new object[]{ new HMACSHA256(), invalidBase64EncodedString },

                new object[]{ new HMACSHA384(), null },
                new object[]{ new HMACSHA384(), string.Empty },
                new object[]{ new HMACSHA384(), WhiteSpaceString },
                new object[]{ new HMACSHA384(), invalidHexadecimalEncodedString },
                new object[]{ new HMACSHA384(), invalidBase64EncodedString },

                new object[]{ new HMACSHA512(), null },
                new object[]{ new HMACSHA512(), string.Empty },
                new object[]{ new HMACSHA512(), WhiteSpaceString },
                new object[]{ new HMACSHA512(), invalidHexadecimalEncodedString },
                new object[]{ new HMACSHA512(), invalidBase64EncodedString },
            };
        }

        private static IEnumerable<object[]> GetHMACAlgorithmInputTextOffsetOptionsAndVerificationHMACString()
        {
            var additionalDataLength = 10;
            var inputText = PlainTestString;
            var inputTextWithAdditionalData = $"{new string('a', additionalDataLength)}{inputText}{new string('z', additionalDataLength)}";
            var secretKeyHexEncoded = _hexadecimalEncoder.EncodeToString(SecretKey);
            var secretKeyBase64Encoded = _base64Encoder.EncodeToString(SecretKey);

            return new List<object[]>()
            {
                new object[]{ new HMACMD5(secretKeyHexEncoded, EncodingType.Hexadecimal), inputText, new OffsetOptions(), TestStringHmacShaMd5HashHexEncoded },
                //new object[]{ new MD5(EncodingType.Hexadecimal), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringHmacShaMd5HashHexEncoded },
                new object[]{ new HMACMD5(secretKeyBase64Encoded, EncodingType.Base64), inputText, new OffsetOptions(), TestStringHmacShaMd5HashBase64Encoded },
                //new object[]{ new MD5(EncodingType.Base64), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringMd5HashBase64Encoded },

                //new object[]{ new SHA1(EncodingType.Hexadecimal), inputText, new OffsetOptions(), TestStringSha1HashHexEncoded },
                //new object[]{ new SHA1(EncodingType.Hexadecimal), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha1HashHexEncoded },
                //new object[]{ new SHA1(EncodingType.Base64), inputText, new OffsetOptions(), TestStringSha1HashBase64Encoded },
                //new object[]{ new SHA1(EncodingType.Base64), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha1HashBase64Encoded },

                //new object[]{ new SHA256(EncodingType.Hexadecimal), inputText, new OffsetOptions(), TestStringSha256HashHexEncoded },
                //new object[]{ new SHA256(EncodingType.Hexadecimal), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha256HashHexEncoded },
                //new object[]{ new SHA256(EncodingType.Base64), inputText, new OffsetOptions(), TestStringSha256HashBase64Encoded },
                //new object[]{ new SHA256(EncodingType.Base64), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha256HashBase64Encoded },

                //new object[]{ new SHA384(EncodingType.Hexadecimal), inputText, new OffsetOptions(), TestStringSha384HashHexEncoded },
                //new object[]{ new SHA384(EncodingType.Hexadecimal), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha384HashHexEncoded },
                //new object[]{ new SHA384(EncodingType.Base64), inputText, new OffsetOptions(), TestStringSha384HashBase64Encoded },
                //new object[]{ new SHA384(EncodingType.Base64), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha384HashBase64Encoded },

                //new object[]{ new SHA512(EncodingType.Hexadecimal), inputText, new OffsetOptions(), TestStringSha512HashHexEncoded },
                //new object[]{ new SHA512(EncodingType.Hexadecimal), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha512HashHexEncoded },
                //new object[]{ new SHA512(EncodingType.Base64), inputText, new OffsetOptions(), TestStringSha512HashBase64Encoded },
                //new object[]{ new SHA512(EncodingType.Base64), inputTextWithAdditionalData, new OffsetOptions(additionalDataLength, inputText.Length), TestStringSha512HashBase64Encoded },
            };
        }

        private static IEnumerable<object[]> GetHashAlgorithmInputDataOffsetOptionsAndExpectedHashString()
        {
            var additionalDataLength = 10;
            var inputText = PlainTestString;
            var inputTextBytes = inputText.ToUTF8Bytes();
            var inputTextWithAdditionalData = $"{new string('a', additionalDataLength)}{inputText}{new string('z', additionalDataLength)}";
            var inputTextWithAdditionalDataBytes = inputTextWithAdditionalData.ToUTF8Bytes();
            var secretKeyHexEncoded = _hexadecimalEncoder.EncodeToString(SecretKey);
            var secretKeyBase64Encoded = _base64Encoder.EncodeToString(SecretKey);

            return new List<object[]>()
            {
                new object[]{ new HMACMD5(secretKeyHexEncoded, EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), TestStringHmacShaMd5HashHexEncoded },
                //new object[]{ new MD5(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringMd5HashHexEncoded },
                new object[]{ new HMACMD5(secretKeyBase64Encoded, EncodingType.Base64), inputTextBytes, new OffsetOptions(), TestStringHmacShaMd5HashBase64Encoded },
                //new object[]{ new MD5(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringMd5HashBase64Encoded },

                //new object[]{ new SHA1(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), TestStringSha1HashHexEncoded },
                //new object[]{ new SHA1(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha1HashHexEncoded },
                //new object[]{ new SHA1(EncodingType.Base64), inputTextBytes, new OffsetOptions(), TestStringSha1HashBase64Encoded },
                //new object[]{ new SHA1(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha1HashBase64Encoded },

                //new object[]{ new SHA256(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), TestStringSha256HashHexEncoded },
                //new object[]{ new SHA256(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha256HashHexEncoded },
                //new object[]{ new SHA256(EncodingType.Base64), inputTextBytes, new OffsetOptions(), TestStringSha256HashBase64Encoded },
                //new object[]{ new SHA256(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha256HashBase64Encoded },

                //new object[]{ new SHA384(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), TestStringSha384HashHexEncoded },
                //new object[]{ new SHA384(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha384HashHexEncoded },
                //new object[]{ new SHA384(EncodingType.Base64), inputTextBytes, new OffsetOptions(), TestStringSha384HashBase64Encoded },
                //new object[]{ new SHA384(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha384HashBase64Encoded },

                //new object[]{ new SHA512(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), TestStringSha512HashHexEncoded },
                //new object[]{ new SHA512(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha512HashHexEncoded },
                //new object[]{ new SHA512(EncodingType.Base64), inputTextBytes, new OffsetOptions(), TestStringSha512HashBase64Encoded },
                //new object[]{ new SHA512(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), TestStringSha512HashBase64Encoded },
            };
        }

        private static IEnumerable<object[]> GetHMACAlgorithmFilePathOffsetOptionsAndExpectedHMACString()
        {
            var tempFilePath = Path.GetTempFileName();
            File.WriteAllText(tempFilePath, PlainTestString);

            var tempFilePathWithAdditionalData = Path.GetTempFileName();
            var additionalDataLength = 10;
            var textWithAdditionalData = $"{new string('a', additionalDataLength)}{PlainTestString}{new string('z', additionalDataLength)}";
            File.WriteAllText(tempFilePathWithAdditionalData, textWithAdditionalData);
            var secretKeyHexEncoded = _hexadecimalEncoder.EncodeToString(SecretKey);
            var secretKeyBase64Encoded = _base64Encoder.EncodeToString(SecretKey);

            return new List<object[]>()
            {
                new object[]{ new HMACMD5(secretKeyHexEncoded, EncodingType.Hexadecimal), tempFilePath, new LongOffsetOptions(), TestStringHmacShaMd5HashHexEncoded },
                //new object[]{ new MD5(EncodingType.Hexadecimal), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), TestStringMd5HashHexEncoded },
                new object[]{ new HMACMD5(secretKeyBase64Encoded, EncodingType.Base64), tempFilePath, new LongOffsetOptions(), TestStringHmacShaMd5HashBase64Encoded },
                //new object[]{ new MD5(EncodingType.Base64), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), TestStringMd5HashBase64Encoded },

                //new object[]{ new SHA1(EncodingType.Hexadecimal), tempFilePath, new LongOffsetOptions(), TestStringSha1HashHexEncoded },
                //new object[]{ new SHA1(EncodingType.Hexadecimal), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), TestStringSha1HashHexEncoded },
                //new object[]{ new SHA1(EncodingType.Base64), tempFilePath, new LongOffsetOptions(), TestStringSha1HashBase64Encoded },
                //new object[]{ new SHA1(EncodingType.Base64), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), TestStringSha1HashBase64Encoded },

                //new object[]{ new SHA256(EncodingType.Hexadecimal), tempFilePath, new LongOffsetOptions(), TestStringSha256HashHexEncoded },
                //new object[]{ new SHA256(EncodingType.Hexadecimal), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), TestStringSha256HashHexEncoded },
                //new object[]{ new SHA256(EncodingType.Base64), tempFilePath, new LongOffsetOptions(), TestStringSha256HashBase64Encoded },
                //new object[]{ new SHA256(EncodingType.Base64), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), TestStringSha256HashBase64Encoded },

                //new object[]{ new SHA384(EncodingType.Hexadecimal), tempFilePath, new LongOffsetOptions(), TestStringSha384HashHexEncoded },
                //new object[]{ new SHA384(EncodingType.Hexadecimal), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), TestStringSha384HashHexEncoded },
                //new object[]{ new SHA384(EncodingType.Base64), tempFilePath, new LongOffsetOptions(), TestStringSha384HashBase64Encoded },
                //new object[]{ new SHA384(EncodingType.Base64), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), TestStringSha384HashBase64Encoded },

                //new object[]{ new SHA512(EncodingType.Hexadecimal), tempFilePath, new LongOffsetOptions(), TestStringSha512HashHexEncoded },
                //new object[]{ new SHA512(EncodingType.Hexadecimal), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), TestStringSha512HashHexEncoded },
                //new object[]{ new SHA512(EncodingType.Base64), tempFilePath, new LongOffsetOptions(), TestStringSha512HashBase64Encoded },
                //new object[]{ new SHA512(EncodingType.Base64), tempFilePathWithAdditionalData, new LongOffsetOptions(additionalDataLength, PlainTestString.Length), TestStringSha512HashBase64Encoded },
            };
        }

        private static IEnumerable<object[]> GetHMACAlgorithmInputDataOffsetOptionsAndExpectedVerificationHMAC()
        {
            var additionalDataLength = 10;
            var inputText = PlainTestString;
            var inputTextBytes = inputText.ToUTF8Bytes();
            var inputTextWithAdditionalData = $"{new string('a', additionalDataLength)}{inputText}{new string('z', additionalDataLength)}";
            var inputTextWithAdditionalDataBytes = inputTextWithAdditionalData.ToUTF8Bytes();

            var md5VerificationHashFromHexEncodedString = TestStringHmacShaMd5HashHexEncoded.ToBytesFromHexadecimalString();
            var md5VerificationHashFromBase64EncodedString = TestStringHmacShaMd5HashBase64Encoded.ToBytesFromBase64String();

            //var sha1VerificationHashFromHexEncodedString = TestStringSha1HashHexEncoded.ToBytesFromHexadecimalString();
            //var sha1VerificationHashFromBase64EncodedString = TestStringSha1HashBase64Encoded.ToBytesFromBase64String();

            //var sha256VerificationHashFromHexEncodedString = TestStringSha256HashHexEncoded.ToBytesFromHexadecimalString();
            //var sha256VerificationHashFromBase64EncodedString = TestStringSha256HashBase64Encoded.ToBytesFromBase64String();

            //var sha384VerificationHashFromHexEncodedString = TestStringSha384HashHexEncoded.ToBytesFromHexadecimalString();
            //var sha384VerificationHashFromBase64EncodedString = TestStringSha384HashBase64Encoded.ToBytesFromBase64String();

            //var sha512VerificationHashFromHexEncodedString = TestStringSha512HashHexEncoded.ToBytesFromHexadecimalString();
            //var sha512VerificationHashFromBase64EncodedString = TestStringSha512HashBase64Encoded.ToBytesFromBase64String();

            var secretKeyHexEncoded = _hexadecimalEncoder.EncodeToString(SecretKey);
            var secretKeyBase64Encoded = _base64Encoder.EncodeToString(SecretKey);

            return new List<object[]>()
            {
                new object[]{ new HMACMD5(secretKeyHexEncoded, EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), md5VerificationHashFromHexEncodedString },
                //new object[]{ new MD5(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), md5VerificationHashFromHexEncodedString },
                new object[]{ new HMACMD5(secretKeyBase64Encoded, EncodingType.Base64), inputTextBytes, new OffsetOptions(), md5VerificationHashFromBase64EncodedString },
                //new object[]{ new MD5(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), md5VerificationHashFromBase64EncodedString },

                //new object[]{ new SHA1(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), sha1VerificationHashFromHexEncodedString },
                //new object[]{ new SHA1(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha1VerificationHashFromHexEncodedString },
                //new object[]{ new SHA1(EncodingType.Base64), inputTextBytes, new OffsetOptions(), sha1VerificationHashFromBase64EncodedString },
                //new object[]{ new SHA1(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha1VerificationHashFromBase64EncodedString },

                //new object[]{ new SHA256(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), sha256VerificationHashFromHexEncodedString },
                //new object[]{ new SHA256(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha256VerificationHashFromHexEncodedString },
                //new object[]{ new SHA256(EncodingType.Base64), inputTextBytes, new OffsetOptions(), sha256VerificationHashFromBase64EncodedString },
                //new object[]{ new SHA256(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha256VerificationHashFromBase64EncodedString },

                //new object[]{ new SHA384(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), sha384VerificationHashFromHexEncodedString },
                //new object[]{ new SHA384(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha384VerificationHashFromHexEncodedString },
                //new object[]{ new SHA384(EncodingType.Base64), inputTextBytes, new OffsetOptions(), sha384VerificationHashFromBase64EncodedString },
                //new object[]{ new SHA384(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha384VerificationHashFromBase64EncodedString },

                //new object[]{ new SHA512(EncodingType.Hexadecimal), inputTextBytes, new OffsetOptions(), sha512VerificationHashFromHexEncodedString },
                //new object[]{ new SHA512(EncodingType.Hexadecimal), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha512VerificationHashFromHexEncodedString },
                //new object[]{ new SHA512(EncodingType.Base64), inputTextBytes, new OffsetOptions(), sha512VerificationHashFromBase64EncodedString },
                //new object[]{ new SHA512(EncodingType.Base64), inputTextWithAdditionalDataBytes, new OffsetOptions(additionalDataLength, inputTextBytes.Length), sha512VerificationHashFromBase64EncodedString },
            };
        }
    }
}