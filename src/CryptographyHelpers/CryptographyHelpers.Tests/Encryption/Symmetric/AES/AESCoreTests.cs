using CryptographyHelpers.Encryption.Symmetric.AES;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Options;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using FluentAssertions;
using FluentAssertions.Events;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CryptographyHelpers.Tests.Encryption.Symmetric.AES
{
    [TestClass]
    public class AESCoreTests
    {
        private const string PlainStringTest = "This is a test string!";
        private static IEncoder _base64Encoder;
        private static IEncoder _hexadecimalEncoder;
        private static AESCore _aes;
        private static IMonitor<AESCore> _monitoredAes;


        [ClassInitialize]
        public static void Initialize(TestContext _)
        {
            _aes = new(AESKeySizes.KeySize128Bits);
            _monitoredAes = _aes.Monitor();
            _base64Encoder = InternalServiceLocator.Instance.GetService<IBase64>();
            _hexadecimalEncoder = InternalServiceLocator.Instance.GetService<IHexadecimal>();
        }

        [ClassCleanup]
        public static void Cleanup()
        {
            _aes.Dispose();
            _monitoredAes.Dispose();
        }

        [TestMethod]
        [DynamicData(nameof(GetInvalidKeysAndIVs), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor1_WhenProvidedInvalidKeyOrIV(byte[] invalidKey, byte[] invalidIV)
        {
            Action act = () => { AESCore aes = new(invalidKey, invalidIV, CipherMode.CBC, PaddingMode.PKCS7); };

            act.Should().Throw<Exception>();
        }

        [TestMethod]
        [DynamicData(nameof(GetInvalidEncodedKeysAndIVs), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor2_WhenProvidedInvalidEncodedKeyOrIV(string invalidEncodedKey, string invalidEncodedIV, EncodingType encodingType)
        {
            Action act = () => { AESCore aes = new(invalidEncodedKey, invalidEncodedIV, CipherMode.CBC, PaddingMode.PKCS7, encodingType); };

            act.Should().Throw<Exception>();
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldReturnSuccessFalse_InEncrypt_WhenProvidedInvalidInputData(byte[] invalidInputData)
        {
            var aesEncryptionResult = _aes.Encrypt(invalidInputData);

            aesEncryptionResult.Success.Should().BeFalse();
            aesEncryptionResult.Message.Should().Be(MessageStrings.Encryption_InputBytesRequired);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldReturnSuccessFalse_InEncryptText_WhenProvidedInvalidInputText(string invalidInputText)
        {
            var aesTextEncryptionResult = _aes.EncryptText(invalidInputText);

            aesTextEncryptionResult.Success.Should().BeFalse();
            aesTextEncryptionResult.Message.Should().Be(MessageStrings.Encryption_InputStringRequired);
        }

        [TestMethod]
        [DynamicData(nameof(GetInvalidFilePath), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InEncryptFile_WhenProvidedInvalidInputSourceFilePath(string invalidSourceFilePath)
        {
            var aesFileEncryptionResult = _aes.EncryptFile(invalidSourceFilePath, invalidSourceFilePath);

            aesFileEncryptionResult.Success.Should().BeFalse();
            aesFileEncryptionResult.Message.Should().StartWith(MessageStrings.File_PathNotFound);
        }

        [TestMethod]
        public void ShouldReturnSuccessFalse_InEncryptFile_WhenProvidedEqualsInputSourceAndEncryptedFilePath()
        {
            var filePath = Path.GetTempFileName();
            var aesFileEncryptionResult = _aes.EncryptFile(filePath, filePath);

            aesFileEncryptionResult.Success.Should().BeFalse();
            aesFileEncryptionResult.Message.Should().Be(MessageStrings.File_SourceAndDestinationPathsEqual);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldReturnSuccessFalse_InDecrypt_WhenProvidedInvalidInputData(byte[] invalidInputData)
        {
            var aesDecryptionResult = _aes.Decrypt(invalidInputData);

            aesDecryptionResult.Success.Should().BeFalse();
            aesDecryptionResult.Message.Should().Be(MessageStrings.Decryption_InputBytesRequired);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldReturnSuccessFalse_InDecryptText_WhenProvidedInvalidInputText(string invalidInputText)
        {
            var aesTextDecryptionResult = _aes.DecryptText(invalidInputText);

            aesTextDecryptionResult.Success.Should().BeFalse();
            aesTextDecryptionResult.Message.Should().Be(MessageStrings.Decryption_InputStringRequired);
        }

        [TestMethod]
        [DynamicData(nameof(GetInvalidFilePath), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InDecryptFile_WhenProvidedInvalidInputEncryptedFilePath(string invalidEncryptedFilePath)
        {
            var aesFileDecryptionResult = _aes.DecryptFile(invalidEncryptedFilePath, invalidEncryptedFilePath);

            aesFileDecryptionResult.Success.Should().BeFalse();
            aesFileDecryptionResult.Message.Should().StartWith(MessageStrings.File_PathNotFound);
        }

        [TestMethod]
        public void ShouldReturnSuccessFalse_InDecryptFile_WhenProvidedEqualsInputEncryptedAndDecryptedFilePath()
        {
            var filePath = Path.GetTempFileName();
            var aesFileDecryptionResult = _aes.DecryptFile(filePath, filePath);

            aesFileDecryptionResult.Success.Should().BeFalse();
            aesFileDecryptionResult.Message.Should().Be(MessageStrings.File_SourceAndDestinationPathsEqual);
        }

        [TestMethod]
        [DynamicData(nameof(GetOffsetOptionsAndExpectedData), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptDataSucessfully_WithAndWithoutOffsetOptions_InEncrypt(byte[] inputData, OffsetOptions offsetOptions, byte[] expectedData)
        {
            var aesEncryptionResult = _aes.Encrypt(inputData, offsetOptions);

            if (!aesEncryptionResult.Success)
            {
                Assert.Fail(aesEncryptionResult.Message);
            }

            var aesDecryptionResult = _aes.Decrypt(aesEncryptionResult.EncryptedData);

            if (!aesDecryptionResult.Success)
            {
                Assert.Fail(aesDecryptionResult.Message);
            }

            aesDecryptionResult.DecryptedData.Should().BeEquivalentTo(expectedData);
        }

        [TestMethod]
        public void ShouldEncryptAndDecryptDataSucessfully_WithoutOffsetOptions_InDecrypt()
        {
            var dataBytes = PlainStringTest.ToUTF8Bytes();

            var aesEncryptionResult = _aes.Encrypt(dataBytes);

            if (!aesEncryptionResult.Success)
            {
                Assert.Fail(aesEncryptionResult.Message);
            }

            var aesDecryptionResult = _aes.Decrypt(aesEncryptionResult.EncryptedData);

            if (!aesDecryptionResult.Success)
            {
                Assert.Fail(aesDecryptionResult.Message);
            }

            aesDecryptionResult.DecryptedData.Should().BeEquivalentTo(dataBytes);
        }

        [TestMethod]
        public void ShouldEncryptAndDecryptDataSucessfully_WithOffsetOptions_InDecrypt()
        {
            var dataBytes = PlainStringTest.ToUTF8Bytes();

            var aesEncryptionResult = _aes.Encrypt(dataBytes);

            if (!aesEncryptionResult.Success)
            {
                Assert.Fail(aesEncryptionResult.Message);
            }

            var additionalDataAtBeginLenght = 10;
            var additionalDataAtBegin = CryptographyUtils.GenerateRandomBytes(additionalDataAtBeginLenght);
            var additionalDataAtEndLenght = 10;
            var additionalDataAtEnd = CryptographyUtils.GenerateRandomBytes(additionalDataAtEndLenght);
            var encryptedDataWithAdditionalData = new byte[additionalDataAtBeginLenght + aesEncryptionResult.EncryptedData.Length + additionalDataAtEndLenght];
            Array.Copy(additionalDataAtBegin, 0, encryptedDataWithAdditionalData, 0, additionalDataAtBeginLenght);
            Array.Copy(aesEncryptionResult.EncryptedData, 0, encryptedDataWithAdditionalData, additionalDataAtBeginLenght, aesEncryptionResult.EncryptedData.Length);
            Array.Copy(additionalDataAtEnd, 0, encryptedDataWithAdditionalData, additionalDataAtBeginLenght + aesEncryptionResult.EncryptedData.Length, additionalDataAtEndLenght);

            var aesDecryptionResult = _aes.Decrypt(encryptedDataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLenght, aesEncryptionResult.EncryptedData.Length));

            if (!aesDecryptionResult.Success)
            {
                Assert.Fail(aesDecryptionResult.Message);
            }

            aesDecryptionResult.DecryptedData.Should().BeEquivalentTo(dataBytes);
        }

        [TestMethod]
        [DynamicData(nameof(GetOffsetOptionsAndExpectedText), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptTextSucessfully_WithAndWithoutOffsetOption_InEncryptText(string inputText, OffsetOptions offsetOptions, string expectedText)
        {
            var aesTextEncryptionResult = _aes.EncryptText(inputText, offsetOptions);

            if (!aesTextEncryptionResult.Success)
            {
                Assert.Fail(aesTextEncryptionResult.Message);
            }

            var aesTextDecryptionResult = _aes.DecryptText(aesTextEncryptionResult.EncodedEncryptedText);

            if (!aesTextDecryptionResult.Success)
            {
                Assert.Fail(aesTextDecryptionResult.Message);
            }

            aesTextDecryptionResult.DecryptedText.Should().Be(expectedText);
        }

        [TestMethod]
        public void ShouldEncryptAndDecryptTextSucessfully_WithOffsetOptions_InDecryptText()
        {
            var text = PlainStringTest;

            var aesTextEncryptionResult = _aes.EncryptText(text);

            if (!aesTextEncryptionResult.Success)
            {
                Assert.Fail(aesTextEncryptionResult.Message);
            }

            var additionalTextAtBeginLength = 10;
            var additionalTextAtBegin = new string('a', additionalTextAtBeginLength);
            var additionalTextAtEndLength = 10;
            var additionalTextAtEnd = new string('z', additionalTextAtEndLength);
            var encryptedTextWithAdditionalTexts = $"{additionalTextAtBegin}{aesTextEncryptionResult.EncodedEncryptedText}{additionalTextAtEnd}";

            var aesTextDecryptionResult = _aes.DecryptText(encryptedTextWithAdditionalTexts, new OffsetOptions(additionalTextAtBeginLength, aesTextEncryptionResult.EncodedEncryptedText.Length));

            if (!aesTextDecryptionResult.Success)
            {
                Assert.Fail(aesTextDecryptionResult.Message);
            }

            aesTextDecryptionResult.DecryptedText.Should().BeEquivalentTo(text);
        }

        [TestMethod]
        public void ShouldEncryptAndDecryptFileSucessfully()
        {
            var testFilePath = Path.GetTempFileName();
            CreateFileAndWriteText(testFilePath, PlainStringTest);
            var encryptedTestFilePath = Path.ChangeExtension(testFilePath, ".encrypted");
            _aes.EncryptFile(testFilePath, encryptedTestFilePath);
            var aesFileEncryptionResult = _aes.EncryptFile(testFilePath, encryptedTestFilePath);

            if (!aesFileEncryptionResult.Success)
            {
                Assert.Fail(aesFileEncryptionResult.Message);
            }

            var decryptedTestFilePath = Path.ChangeExtension(encryptedTestFilePath, ".decrypted");
            var aesDecryptionResult = _aes.DecryptFile(encryptedTestFilePath, decryptedTestFilePath);

            if (!aesDecryptionResult.Success)
            {
                Assert.Fail(aesDecryptionResult.Message);
            }

            _monitoredAes.Should().Raise(nameof(AESCore.OnEncryptFileProgress));
            _monitoredAes.Should().Raise(nameof(AESCore.OnDecryptFileProgress));
            aesDecryptionResult.Success.Should().BeTrue();
            ReadFileText(decryptedTestFilePath).Should().Be(PlainStringTest);
        }

        [TestMethod]
        [DynamicData(nameof(GetTextAndLongOffsetOptions), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptFileSucessfully_WithAndWithoutLongOffsetOptions_InEncryptFile(string expectedText, LongOffsetOptions offsetOptions)
        {
            var testFilePath = Path.GetTempFileName();
            CreateFileAndWriteText(testFilePath, PlainStringTest);
            var encryptedTestFilePath = Path.ChangeExtension(testFilePath, ".encrypted");

            var aesFileEncryptionResult = _aes.EncryptFile(testFilePath, encryptedTestFilePath, offsetOptions);

            if (!aesFileEncryptionResult.Success)
            {
                Assert.Fail(aesFileEncryptionResult.Message);
            }

            var decryptedTestFilePath = Path.ChangeExtension(encryptedTestFilePath, ".decrypted");
            var aesFileDecryptionResult = _aes.DecryptFile(encryptedTestFilePath, decryptedTestFilePath);

            if (!aesFileDecryptionResult.Success)
            {
                Assert.Fail(aesFileDecryptionResult.Message);
            }

            _monitoredAes.Should().Raise(nameof(AESCore.OnEncryptFileProgress));
            _monitoredAes.Should().Raise(nameof(AESCore.OnDecryptFileProgress));
            aesFileDecryptionResult.Success.Should().BeTrue();
            var decryptedText = ReadFileText(decryptedTestFilePath);
            decryptedText.Should().Be(expectedText);
        }

        [TestMethod]
        public void ShouldEncryptAndDecryptFileSucessfully_WithLongOffsetOptions_InDecryptFile()
        {
            var testFilePath = Path.GetTempFileName();
            CreateFileAndWriteText(testFilePath, PlainStringTest);
            var encryptedTestFilePath = Path.ChangeExtension(testFilePath, ".encrypted");

            var aesFileEncryptionResult = _aes.EncryptFile(testFilePath, encryptedTestFilePath);

            if (!aesFileEncryptionResult.Success)
            {
                Assert.Fail(aesFileEncryptionResult.Message);
            }

            var additionalDataAtBeginLenght = 10L;
            var additionalDataAtBegin = CryptographyUtils.GenerateRandomBytes((int)additionalDataAtBeginLenght);
            var additionalDataAtEndLenght = 10L;
            var additionalDataAtEnd = CryptographyUtils.GenerateRandomBytes((int)additionalDataAtEndLenght);
            var fileData = File.ReadAllBytes(encryptedTestFilePath);
            var fileDataWithAdditionalInfo = new byte[additionalDataAtBeginLenght + fileData.Length + additionalDataAtEndLenght];
            Array.Copy(additionalDataAtBegin, 0, fileDataWithAdditionalInfo, 0, additionalDataAtBeginLenght);
            Array.Copy(fileData, 0, fileDataWithAdditionalInfo, additionalDataAtBeginLenght, fileData.Length);
            Array.Copy(additionalDataAtEnd, 0, fileDataWithAdditionalInfo, additionalDataAtBeginLenght + fileData.Length, additionalDataAtEndLenght);
            File.WriteAllBytes(encryptedTestFilePath, fileDataWithAdditionalInfo);
            var decryptedTestFilePath = Path.ChangeExtension(encryptedTestFilePath, ".decrypted");

            var aesFileDecryptionResult = _aes.DecryptFile(encryptedTestFilePath, decryptedTestFilePath, new LongOffsetOptions(additionalDataAtBeginLenght, fileData.Length));

            if (!aesFileDecryptionResult.Success)
            {
                Assert.Fail(aesFileDecryptionResult.Message);
            }

            _monitoredAes.Should().Raise(nameof(AESCore.OnEncryptFileProgress));
            _monitoredAes.Should().Raise(nameof(AESCore.OnDecryptFileProgress));
            aesFileDecryptionResult.Success.Should().BeTrue();
            var decryptedText = ReadFileText(decryptedTestFilePath);
            decryptedText.Should().Be(PlainStringTest);
        }


        private static IEnumerable<object[]> GetInvalidKeysAndIVs()
        {
            // IV has exactly 128 bits, so in this particular case we can use the same random bytes as 128 bits key and IV for our tests purpose
            var random128BitsKeyIV = CryptographyUtils.GenerateRandom128BitsKey();
            var invalidSizedKeyIV = random128BitsKeyIV.Take(random128BitsKeyIV.Length - 1).ToArray();

            return new List<object[]>()
            {
                new object[]{ null, null },
                new object[]{ null, Array.Empty<byte>() },
                new object[]{ null, invalidSizedKeyIV },

                new object[]{ Array.Empty<byte>(), Array.Empty<byte>(), },
                new object[]{ Array.Empty<byte>(), null, },
                new object[]{ Array.Empty<byte>(), invalidSizedKeyIV, },

                new object[]{ invalidSizedKeyIV, invalidSizedKeyIV, },
                new object[]{ invalidSizedKeyIV, null, },
                new object[]{ invalidSizedKeyIV, Array.Empty<byte>(), },
            };
        }

        private static IEnumerable<object[]> GetInvalidEncodedKeysAndIVs()
        {
            // IV has exactly 128 bits, so in this particular case we can use the same random bytes as 128 bits key and IV for our tests purpose
            var random128BitsKeyIV = CryptographyUtils.GenerateRandom128BitsKey();
            var invalidSizedKeyIV = random128BitsKeyIV.Take(random128BitsKeyIV.Length - 1).ToArray();
            string invalidBase64TestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ=";
            string invalidHexadecimalTestString = "546869732069732061207465737420737472696E672G";

            return new List<object[]>()
            {
                new object[]{ null, null, EncodingType.Base64 },
                new object[]{ null, null, EncodingType.Hexadecimal },
                new object[]{ null, "", EncodingType.Base64 },
                new object[]{ null, "", EncodingType.Hexadecimal },
                new object[]{ null, _base64Encoder.EncodeToString(invalidSizedKeyIV), EncodingType.Base64 },
                new object[]{ null, invalidBase64TestString, EncodingType.Base64 },
                new object[]{ null, _hexadecimalEncoder.EncodeToString(invalidSizedKeyIV), EncodingType.Hexadecimal },
                new object[]{ null, invalidHexadecimalTestString, EncodingType.Hexadecimal },

                new object[]{ "", "", EncodingType.Base64 },
                new object[]{ "", "", EncodingType.Hexadecimal },
                new object[]{ "", null, EncodingType.Hexadecimal },
                new object[]{ "", null, EncodingType.Base64 },
                new object[]{ "", _base64Encoder.EncodeToString(invalidSizedKeyIV), EncodingType.Base64 },
                new object[]{ "", invalidBase64TestString, EncodingType.Base64 },
                new object[]{ "", _hexadecimalEncoder.EncodeToString(invalidSizedKeyIV), EncodingType.Hexadecimal },
                new object[]{ "", invalidHexadecimalTestString, EncodingType.Hexadecimal },

                new object[]{ invalidBase64TestString, invalidBase64TestString, EncodingType.Base64 },
                new object[]{ invalidBase64TestString, null, EncodingType.Base64 },
                new object[]{ invalidBase64TestString, "", EncodingType.Base64 },
                new object[]{ invalidBase64TestString, _base64Encoder.EncodeToString(invalidSizedKeyIV), EncodingType.Base64 },

                new object[]{ _base64Encoder.EncodeToString(invalidSizedKeyIV), _base64Encoder.EncodeToString(invalidSizedKeyIV), EncodingType.Base64 },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKeyIV), invalidBase64TestString, EncodingType.Base64 },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKeyIV), null, EncodingType.Base64 },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKeyIV), "", EncodingType.Base64 },

                new object[]{ invalidHexadecimalTestString, invalidHexadecimalTestString, EncodingType.Hexadecimal },
                new object[]{ invalidHexadecimalTestString, "", EncodingType.Hexadecimal },
                new object[]{ invalidHexadecimalTestString, null, EncodingType.Hexadecimal },
                new object[]{ invalidHexadecimalTestString, _hexadecimalEncoder.EncodeToString(invalidSizedKeyIV), EncodingType.Hexadecimal },

                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKeyIV), _hexadecimalEncoder.EncodeToString(invalidSizedKeyIV), EncodingType.Hexadecimal },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKeyIV), invalidHexadecimalTestString, EncodingType.Hexadecimal },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKeyIV), "", EncodingType.Hexadecimal },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKeyIV), null, EncodingType.Hexadecimal },
            };
        }

        private static IEnumerable<object[]> GetInvalidFilePath()
        {
            var invalidFilePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.txt");

            return new List<object[]>()
            {
                new object[]{ null },
                new object[]{ string.Empty },
                new object[]{ invalidFilePath },
            };
        }

        private static IEnumerable<object[]> GetOffsetOptionsAndExpectedData()
        {
            var data = PlainStringTest.ToUTF8Bytes();
            var truncatedToBeginData = data.Take(PlainStringTest.Length / 2).ToArray();
            var truncatedToEndData = data.Skip(PlainStringTest.Length / 2).Take(PlainStringTest.Length / 2).ToArray();
            var additionalDataAtBeginLength = 10;
            var additionalDataAtBegin = CryptographyUtils.GenerateRandomBytes(additionalDataAtBeginLength);
            var additionalDataAtEndLength = 10;
            var additionalDataAtEnd = CryptographyUtils.GenerateRandomBytes(additionalDataAtEndLength);
            var dataWithAdditionalData = new byte[additionalDataAtBeginLength + data.Length + additionalDataAtEndLength];
            Array.Copy(additionalDataAtBegin, 0, dataWithAdditionalData, 0, additionalDataAtBeginLength);
            Array.Copy(data, 0, dataWithAdditionalData, additionalDataAtBeginLength, data.Length);
            Array.Copy(additionalDataAtEnd, 0, dataWithAdditionalData, additionalDataAtBeginLength + data.Length, additionalDataAtEndLength);

            return new List<object[]>()
            {
                new object[]{ data, new OffsetOptions(), data },
                new object[]{ data, new OffsetOptions(0, truncatedToBeginData.Length), truncatedToBeginData },
                new object[]{ data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), truncatedToEndData },
                new object[]{ dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), data },
            };
        }

        private static IEnumerable<object[]> GetOffsetOptionsAndExpectedText()
        {
            var text = PlainStringTest;
            var truncatedToBeginText = text.Substring(0, text.Length / 2);
            var truncatedToEndText = text.Substring(text.Length / 2, text.Length / 2);

            var additionalTextAtBeginLength = 10;
            var additionalTextAtBegin = new string('a', additionalTextAtBeginLength);
            var additionalTextAtEndLength = 10;
            var additionalTextAtEnd = new string('z', additionalTextAtEndLength);
            var textWithAdditionalTexts = $"{additionalTextAtBegin}{text}{additionalTextAtEnd}";

            return new List<object[]>()
            {
                new object[]{ text, new OffsetOptions(), text },
                new object[]{ text, new OffsetOptions(0, truncatedToBeginText.Length), truncatedToBeginText },
                new object[]{ text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), truncatedToEndText },
                new object[]{ textWithAdditionalTexts, new OffsetOptions(additionalTextAtBeginLength, text.Length), text },
            };
        }

        private static void CreateFileAndWriteText(string filePath, string text) =>
            File.WriteAllText(filePath, text);

        private long GetFileLenght(string filePath) =>
            new FileInfo(filePath).Length;

        private static string ReadFileText(string filePath) =>
            File.ReadAllText(filePath);

        private static IEnumerable<object[]> GetTextAndLongOffsetOptions()
        {
            var splitedStringlenght = PlainStringTest.Length / 2;

            return new List<object[]>()
            {
                new object[]{ PlainStringTest, new LongOffsetOptions(), },
                new object[]{ PlainStringTest.Substring(0, splitedStringlenght), new LongOffsetOptions(offset: 0, count: splitedStringlenght), },
                new object[]{ PlainStringTest.Substring(splitedStringlenght, splitedStringlenght), new LongOffsetOptions(offset: splitedStringlenght, count: splitedStringlenght), },
            };
        }
    }
}