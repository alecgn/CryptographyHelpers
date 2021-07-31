using CryptographyHelpers.Encryption.Symmetric.AES;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace CryptographyHelpers.Tests.Encryption.Symmetric.AES
{
    [TestClass]
    public class AESBaseTests
    {
        private const string WhiteSpaceString = " ";
        private const string PlainTestString = "This is a test string!";
        private static readonly IBase64Encoder _base64Encoder = InternalServiceLocator.Instance.GetService<IBase64Encoder>();
        private static readonly IHexadecimalEncoder _hexadecimalEncoder = InternalServiceLocator.Instance.GetService<IHexadecimalEncoder>();


        [TestMethod]
        [DynamicData(nameof(GetInvalidKeysAndIVs), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor1_WhenProvidedInvalidKeyOrIV(byte[] invalidKey, byte[] invalidIV)
        {
            Action act = () => { using var aes = new AESBase(invalidKey, invalidIV, CipherMode.CBC, PaddingMode.PKCS7); };

            act.Should().Throw<Exception>();
        }

        [TestMethod]
        [DynamicData(nameof(GetInvalidEncodedKeysAndIVs), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor2_WhenProvidedInvalidEncodedKeyOrIV(string invalidEncodedKey, string invalidEncodedIV, EncodingType encodingType)
        {
            Action act = () => { using var aes = new AESBase(invalidEncodedKey, invalidEncodedIV, CipherMode.CBC, PaddingMode.PKCS7, encodingType); };

            act.Should().Throw<Exception>();
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InEncrypt_WhenProvidedInvalidInputData(AESBase aes, byte[] invalidInputData)
        {
            AESEncryptionResult aesEncryptionResult;

            using (aes)
            {
                aesEncryptionResult = aes.Encrypt(invalidInputData);
            }

            aesEncryptionResult.Success.Should().BeFalse();
            aesEncryptionResult.Message.Should().Be(MessageStrings.Encryption_InputBytesRequired);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidInputText), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InEncryptText_WhenProvidedInvalidInputText(AESBase aes, string invalidInputText)
        {
            AESTextEncryptionResult aesTextEncryptionResult;

            using (aes)
            {
                aesTextEncryptionResult = aes.EncryptText(invalidInputText);
            }

            aesTextEncryptionResult.Success.Should().BeFalse();
            aesTextEncryptionResult.Message.Should().Be(MessageStrings.Encryption_InputTextRequired);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidFilePath), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InEncryptFile_WhenProvidedInvalidInputSourceFilePath(AESBase aes, string invalidSourceFilePath)
        {
            AESFileEncryptionResult aesFileEncryptionResult;

            using (aes)
            {
                aesFileEncryptionResult = aes.EncryptFile(invalidSourceFilePath, invalidSourceFilePath);
            }

            aesFileEncryptionResult.Success.Should().BeFalse();
            aesFileEncryptionResult.Message.Should().StartWith(MessageStrings.File_PathNotFound);
        }

        [TestMethod]
        [DynamicData(nameof(GetAES), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InEncryptFile_WhenProvidedEqualsInputSourceAndEncryptedFilePath(AESBase aes)
        {
            AESFileEncryptionResult aesFileEncryptionResult;
            var filePath = Path.GetTempFileName();

            using (aes)
            {
                aesFileEncryptionResult = aes.EncryptFile(filePath, filePath);
            }

            aesFileEncryptionResult.Success.Should().BeFalse();
            aesFileEncryptionResult.Message.Should().Be(MessageStrings.File_SourceAndDestinationPathsEqual);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InDecrypt_WhenProvidedInvalidInputData(AESBase aes, byte[] invalidInputData)
        {
            AESDecryptionResult aesDecryptionResult;

            using (aes)
            {
                aesDecryptionResult = aes.Decrypt(invalidInputData);
            }

            aesDecryptionResult.Success.Should().BeFalse();
            aesDecryptionResult.Message.Should().Be(MessageStrings.Decryption_InputBytesRequired);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidInputText), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InDecryptText_WhenProvidedInvalidInputText(AESBase aes, string invalidInputText)
        {
            AESTextDecryptionResult aesTextDecryptionResult;

            using (aes)
            {
                aesTextDecryptionResult = aes.DecryptText(invalidInputText);
            }

            aesTextDecryptionResult.Success.Should().BeFalse();
            aesTextDecryptionResult.Message.Should().Be(MessageStrings.Decryption_InputTextRequired);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidFilePath), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InDecryptFile_WhenProvidedInvalidInputEncryptedFilePath(AESBase aes, string invalidEncryptedFilePath)
        {
            AESFileDecryptionResult aesFileDecryptionResult;

            using (aes)
            {
                aesFileDecryptionResult = aes.DecryptFile(invalidEncryptedFilePath, invalidEncryptedFilePath);
            }

            aesFileDecryptionResult.Success.Should().BeFalse();
            aesFileDecryptionResult.Message.Should().StartWith(MessageStrings.File_PathNotFound);
        }

        [TestMethod]
        [DynamicData(nameof(GetAES), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InDecryptFile_WhenProvidedEqualsInputEncryptedAndDecryptedFilePath(AESBase aes)
        {
            AESFileDecryptionResult aesFileDecryptionResult;
            var filePath = Path.GetTempFileName();

            using (aes)
            {
                aesFileDecryptionResult = aes.DecryptFile(filePath, filePath);
            }

            aesFileDecryptionResult.Success.Should().BeFalse();
            aesFileDecryptionResult.Message.Should().Be(MessageStrings.File_SourceAndDestinationPathsEqual);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESInputDataOffsetOptionsAndExpecteDecryptedData), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptDataSucessfully_WithAndWithoutOffsetOptions_InEncrypt_And_WithoutOffsetOptions_InDecrypt(AESBase aes, byte[] inputData, OffsetOptions offsetOptions, byte[] expectedDecryptedData)
        {
            AESEncryptionResult aesEncryptionResult;
            AESDecryptionResult aesDecryptionResult;

            using (aes)
            {
                aesEncryptionResult = aes.Encrypt(inputData, offsetOptions);

                if (!aesEncryptionResult.Success)
                {
                    Assert.Fail(aesEncryptionResult.Message);
                }

                aesDecryptionResult = aes.Decrypt(aesEncryptionResult.EncryptedData);

                if (!aesDecryptionResult.Success)
                {
                    Assert.Fail(aesDecryptionResult.Message);
                }
            }

            aesDecryptionResult.DecryptedData.Should().BeEquivalentTo(expectedDecryptedData);
        }

        [TestMethod]
        [DynamicData(nameof(GetAES), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptDataSucessfully_WithOffsetOptions_InDecrypt_And_WithoutOffsetOptions_InEncrypt(AESBase aes)
        {
            AESEncryptionResult aesEncryptionResult;
            AESDecryptionResult aesDecryptionResult;
            var dataBytes = PlainTestString.ToUTF8Bytes();

            using (aes)
            {
                aesEncryptionResult = aes.Encrypt(dataBytes);

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

                aesDecryptionResult = aes.Decrypt(encryptedDataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLenght, aesEncryptionResult.EncryptedData.Length));

                if (!aesDecryptionResult.Success)
                {
                    Assert.Fail(aesDecryptionResult.Message);
                }
            }

            aesDecryptionResult.DecryptedData.Should().BeEquivalentTo(dataBytes);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESInputPlainTextOffsetOptionsAndExpectedDecryptedText), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptTextSucessfully_WithAndWithoutOffsetOption_InEncryptText_And_WithoutOffsetOptions_InDecryptText(AESBase aes, string inputPainText, OffsetOptions offsetOptions, string expectedDecryptedText)
        {
            AESTextEncryptionResult aesTextEncryptionResult;
            AESTextDecryptionResult aesTextDecryptionResult;

            using (aes)
            {
                aesTextEncryptionResult = aes.EncryptText(inputPainText, offsetOptions);

                if (!aesTextEncryptionResult.Success)
                {
                    Assert.Fail(aesTextEncryptionResult.Message);
                }

                aesTextDecryptionResult = aes.DecryptText(aesTextEncryptionResult.EncodedEncryptedText);

                if (!aesTextDecryptionResult.Success)
                {
                    Assert.Fail(aesTextDecryptionResult.Message);
                }
            }

            aesTextDecryptionResult.DecryptedText.Should().Be(expectedDecryptedText);
        }

        [TestMethod]
        [DynamicData(nameof(GetAES), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptTextSucessfully_WithOffsetOptions_InDecryptText_And_WithoutOffsetOptions_InEncryptText(AESBase aes)
        {
            AESTextEncryptionResult aesTextEncryptionResult;
            AESTextDecryptionResult aesTextDecryptionResult;
            var text = PlainTestString;

            using (aes)
            {
                aesTextEncryptionResult = aes.EncryptText(text);

                if (!aesTextEncryptionResult.Success)
                {
                    Assert.Fail(aesTextEncryptionResult.Message);
                }

                var additionalTextAtBeginLength = 10;
                var additionalTextAtBegin = new string('a', additionalTextAtBeginLength);
                var additionalTextAtEndLength = 10;
                var additionalTextAtEnd = new string('z', additionalTextAtEndLength);
                var encryptedTextWithAdditionalTexts = $"{additionalTextAtBegin}{aesTextEncryptionResult.EncodedEncryptedText}{additionalTextAtEnd}";

                aesTextDecryptionResult = aes.DecryptText(encryptedTextWithAdditionalTexts, new OffsetOptions(additionalTextAtBeginLength, aesTextEncryptionResult.EncodedEncryptedText.Length));

                if (!aesTextDecryptionResult.Success)
                {
                    Assert.Fail(aesTextDecryptionResult.Message);
                }
            }

            aesTextDecryptionResult.DecryptedText.Should().BeEquivalentTo(text);
        }

        [TestMethod]
        [DynamicData(nameof(GetAES), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptFileSucessfully(AESBase aes)
        {
            AESFileEncryptionResult aesFileEncryptionResult;
            AESFileDecryptionResult aesFileDecryptionResult;
            var testFilePath = Path.GetTempFileName();
            CreateFileAndWriteText(testFilePath, PlainTestString);
            var encryptedTestFilePath = Path.ChangeExtension(testFilePath, ".encrypted");

            using (aes)
            {
                using (var monitoredAes = aes.Monitor())
                {
                    aesFileEncryptionResult = aes.EncryptFile(testFilePath, encryptedTestFilePath);

                    if (!aesFileEncryptionResult.Success)
                    {
                        Assert.Fail(aesFileEncryptionResult.Message);
                    }

                    var decryptedTestFilePath = Path.ChangeExtension(encryptedTestFilePath, ".decrypted");
                    aesFileDecryptionResult = aes.DecryptFile(encryptedTestFilePath, decryptedTestFilePath);

                    if (!aesFileDecryptionResult.Success)
                    {
                        Assert.Fail(aesFileDecryptionResult.Message);
                    }

                    monitoredAes.Should().Raise(nameof(AESBase.OnEncryptFileProgress));
                    monitoredAes.Should().Raise(nameof(AESBase.OnDecryptFileProgress));
                    aesFileDecryptionResult.Success.Should().BeTrue();
                    ReadFileText(decryptedTestFilePath).Should().Be(PlainTestString);
                }
            }
        }

        [TestMethod]
        [DynamicData(nameof(GetAES), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptFileSucessfully_WithAndWithoutLongOffsetOptions_InEncryptFile_And_WithoutOffsetOptions_InDecryptFile(AESBase aes)
        {
            AESFileEncryptionResult aesFileEncryptionResult;
            AESFileDecryptionResult aesFileDecryptionResult;
            var testFilePath = Path.GetTempFileName();
            var encryptedTestFilePath = Path.ChangeExtension(testFilePath, ".encrypted");

            using (aes)
            {
                using (var monitoredAes = aes.Monitor())
                {
                    var additionalDataAtBeginLenght = 10L;
                    var additionalDataAtBegin = CryptographyUtils.GenerateRandomBytes((int)additionalDataAtBeginLenght);
                    var additionalDataAtEndLenght = 10L;
                    var additionalDataAtEnd = CryptographyUtils.GenerateRandomBytes((int)additionalDataAtEndLenght);
                    var fileData = PlainTestString.ToUTF8Bytes();
                    var fileDataWithAdditionalInfo = new byte[additionalDataAtBeginLenght + fileData.Length + additionalDataAtEndLenght];
                    Array.Copy(additionalDataAtBegin, 0, fileDataWithAdditionalInfo, 0, additionalDataAtBeginLenght);
                    Array.Copy(fileData, 0, fileDataWithAdditionalInfo, additionalDataAtBeginLenght, fileData.Length);
                    Array.Copy(additionalDataAtEnd, 0, fileDataWithAdditionalInfo, additionalDataAtBeginLenght + fileData.Length, additionalDataAtEndLenght);
                    File.WriteAllBytes(testFilePath, fileDataWithAdditionalInfo);
                    aesFileEncryptionResult = aes.EncryptFile(testFilePath, encryptedTestFilePath, new LongOffsetOptions(additionalDataAtBeginLenght, fileData.Length));

                    if (!aesFileEncryptionResult.Success)
                    {
                        Assert.Fail(aesFileEncryptionResult.Message);
                    }

                    var decryptedTestFilePath = Path.ChangeExtension(encryptedTestFilePath, ".decrypted");
                    aesFileDecryptionResult = aes.DecryptFile(encryptedTestFilePath, decryptedTestFilePath);

                    if (!aesFileDecryptionResult.Success)
                    {
                        Assert.Fail(aesFileDecryptionResult.Message);
                    }

                    monitoredAes.Should().Raise(nameof(AESBase.OnEncryptFileProgress));
                    monitoredAes.Should().Raise(nameof(AESBase.OnDecryptFileProgress));
                    aesFileDecryptionResult.Success.Should().BeTrue();
                    var decryptedText = ReadFileText(decryptedTestFilePath);
                    decryptedText.Should().Be(PlainTestString);
                }
            }
        }

        [TestMethod]
        [DynamicData(nameof(GetAES), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptFileSucessfully_WithLongOffsetOptions_InDecryptFile(AESBase aes)
        {
            AESFileEncryptionResult aesFileEncryptionResult;
            AESFileDecryptionResult aesFileDecryptionResult;
            var testFilePath = Path.GetTempFileName();
            CreateFileAndWriteText(testFilePath, PlainTestString);
            var encryptedTestFilePath = Path.ChangeExtension(testFilePath, ".encrypted");

            using (aes)
            {
                using (var monitoredAes = aes.Monitor())
                {
                    aesFileEncryptionResult = aes.EncryptFile(testFilePath, encryptedTestFilePath);

                    if (!aesFileEncryptionResult.Success)
                    {
                        Assert.Fail(aesFileEncryptionResult.Message);
                    }

                    var additionalDataAtBeginLenght = 10L;
                    var additionalDataAtBegin = CryptographyUtils.GenerateRandomBytes((int)additionalDataAtBeginLenght);
                    var additionalDataAtEndLenght = 10L;
                    var additionalDataAtEnd = CryptographyUtils.GenerateRandomBytes((int)additionalDataAtEndLenght);
                    var encryptedFileData = File.ReadAllBytes(encryptedTestFilePath);
                    var encryptedFileDataWithAdditionalInfo = new byte[additionalDataAtBeginLenght + encryptedFileData.Length + additionalDataAtEndLenght];
                    Array.Copy(additionalDataAtBegin, 0, encryptedFileDataWithAdditionalInfo, 0, additionalDataAtBeginLenght);
                    Array.Copy(encryptedFileData, 0, encryptedFileDataWithAdditionalInfo, additionalDataAtBeginLenght, encryptedFileData.Length);
                    Array.Copy(additionalDataAtEnd, 0, encryptedFileDataWithAdditionalInfo, additionalDataAtBeginLenght + encryptedFileData.Length, additionalDataAtEndLenght);
                    // overwrites previous encrypted file with additional data at begin and at end
                    File.WriteAllBytes(encryptedTestFilePath, encryptedFileDataWithAdditionalInfo);
                    var decryptedTestFilePath = Path.ChangeExtension(encryptedTestFilePath, ".decrypted");

                    aesFileDecryptionResult = aes.DecryptFile(encryptedTestFilePath, decryptedTestFilePath, new LongOffsetOptions(additionalDataAtBeginLenght, encryptedFileData.Length));

                    if (!aesFileDecryptionResult.Success)
                    {
                        Assert.Fail(aesFileDecryptionResult.Message);
                    }

                    monitoredAes.Should().Raise(nameof(AESBase.OnEncryptFileProgress));
                    monitoredAes.Should().Raise(nameof(AESBase.OnDecryptFileProgress));
                    aesFileDecryptionResult.Success.Should().BeTrue();
                    var decryptedText = ReadFileText(decryptedTestFilePath);
                    decryptedText.Should().Be(PlainTestString);
                }
            }
        }


        private static IEnumerable<object[]> GetInvalidKeysAndIVs()
        {

            var random128BitsKey = CryptographyUtils.GenerateRandom128BitsKey();
            var random192BitsKey = CryptographyUtils.GenerateRandom192BitsKey();
            var random256BitsKey = CryptographyUtils.GenerateRandom256BitsKey();
            var invalidSizedKey1 = random128BitsKey.Take(random128BitsKey.Length - 1).ToArray();
            var invalidSizedKey2 = random192BitsKey.Take(random192BitsKey.Length - 1).ToArray();
            var invalidSizedKey3 = random256BitsKey.Take(random256BitsKey.Length - 1).ToArray();
            // IV has exactly 128 bits, so in this particular case we can use the same random bytes from 128 bits key
            var invalidSizedIV = random128BitsKey.Take(random128BitsKey.Length - 1).ToArray();

            return new List<object[]>()
            {
                new object[]{ null, null },
                new object[]{ null, Array.Empty<byte>() },
                new object[]{ null, invalidSizedIV },

                new object[]{ Array.Empty<byte>(), Array.Empty<byte>() },
                new object[]{ Array.Empty<byte>(), null, },
                new object[]{ Array.Empty<byte>(), invalidSizedIV, },

                new object[]{ invalidSizedKey1, null },
                new object[]{ invalidSizedKey1, Array.Empty<byte>() },
                new object[]{ invalidSizedKey1, invalidSizedIV },

                new object[]{ invalidSizedKey2, null },
                new object[]{ invalidSizedKey2, Array.Empty<byte>() },
                new object[]{ invalidSizedKey2, invalidSizedIV },

                new object[]{ invalidSizedKey3, null },
                new object[]{ invalidSizedKey1, Array.Empty<byte>() },
                new object[]{ invalidSizedKey3, invalidSizedIV },
            };
        }

        private static IEnumerable<object[]> GetInvalidEncodedKeysAndIVs()
        {
            var random128BitsKey = CryptographyUtils.GenerateRandom128BitsKey();
            var random192BitsKey = CryptographyUtils.GenerateRandom192BitsKey();
            var random256BitsKey = CryptographyUtils.GenerateRandom256BitsKey();
            var invalidSizedKey1 = random128BitsKey.Take(random128BitsKey.Length - 1).ToArray();
            var invalidSizedKey2 = random192BitsKey.Take(random192BitsKey.Length - 1).ToArray();
            var invalidSizedKey3 = random256BitsKey.Take(random256BitsKey.Length - 1).ToArray();
            // IV has exactly 128 bits, so in this particular case we can use the same random bytes from 128 bits key
            var invalidSizedIV = random128BitsKey.Take(random128BitsKey.Length - 1).ToArray();
            string invalidBase64TestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ=";
            string invalidHexadecimalTestString = "546869732069732061207465737420737472696E672G";

            return new List<object[]>()
            {
                new object[]{ null, null, EncodingType.Base64 },
                new object[]{ null, null, EncodingType.Hexadecimal },
                new object[]{ null, string.Empty, EncodingType.Base64 },
                new object[]{ null, string.Empty, EncodingType.Hexadecimal },
                new object[]{ null, WhiteSpaceString, EncodingType.Base64 },
                new object[]{ null, WhiteSpaceString, EncodingType.Hexadecimal },
                new object[]{ null, _base64Encoder.EncodeToString(invalidSizedIV), EncodingType.Base64 },
                new object[]{ null, invalidBase64TestString, EncodingType.Base64 },
                new object[]{ null, _hexadecimalEncoder.EncodeToString(invalidSizedIV), EncodingType.Hexadecimal },
                new object[]{ null, invalidHexadecimalTestString, EncodingType.Hexadecimal },

                new object[]{ string.Empty, null, EncodingType.Base64 },
                new object[]{ string.Empty, null, EncodingType.Hexadecimal },
                new object[]{ string.Empty, string.Empty, EncodingType.Base64 },
                new object[]{ string.Empty, string.Empty, EncodingType.Hexadecimal },
                new object[]{ string.Empty, WhiteSpaceString, EncodingType.Base64 },
                new object[]{ string.Empty, WhiteSpaceString, EncodingType.Hexadecimal },
                new object[]{ string.Empty, _base64Encoder.EncodeToString(invalidSizedIV), EncodingType.Base64 },
                new object[]{ string.Empty, invalidBase64TestString, EncodingType.Base64 },
                new object[]{ string.Empty, _hexadecimalEncoder.EncodeToString(invalidSizedIV), EncodingType.Hexadecimal },
                new object[]{ string.Empty, invalidHexadecimalTestString, EncodingType.Hexadecimal },

                new object[]{ WhiteSpaceString, null, EncodingType.Base64 },
                new object[]{ WhiteSpaceString, null, EncodingType.Hexadecimal },
                new object[]{ WhiteSpaceString, string.Empty, EncodingType.Base64 },
                new object[]{ WhiteSpaceString, string.Empty, EncodingType.Hexadecimal },
                new object[]{ WhiteSpaceString, WhiteSpaceString, EncodingType.Base64 },
                new object[]{ WhiteSpaceString, WhiteSpaceString, EncodingType.Hexadecimal },
                new object[]{ WhiteSpaceString, _base64Encoder.EncodeToString(invalidSizedIV), EncodingType.Base64 },
                new object[]{ WhiteSpaceString, invalidBase64TestString, EncodingType.Base64 },
                new object[]{ WhiteSpaceString, _hexadecimalEncoder.EncodeToString(invalidSizedIV), EncodingType.Hexadecimal },
                new object[]{ WhiteSpaceString, invalidHexadecimalTestString, EncodingType.Hexadecimal },

                new object[]{ invalidBase64TestString, invalidBase64TestString, EncodingType.Base64 },
                new object[]{ invalidBase64TestString, null, EncodingType.Base64 },
                new object[]{ invalidBase64TestString, string.Empty, EncodingType.Base64 },
                new object[]{ invalidBase64TestString, WhiteSpaceString, EncodingType.Base64 },
                new object[]{ invalidBase64TestString, _base64Encoder.EncodeToString(invalidSizedIV), EncodingType.Base64 },

                new object[]{ invalidHexadecimalTestString, invalidHexadecimalTestString, EncodingType.Hexadecimal },
                new object[]{ invalidHexadecimalTestString, string.Empty, EncodingType.Hexadecimal },
                new object[]{ invalidHexadecimalTestString, WhiteSpaceString, EncodingType.Hexadecimal },
                new object[]{ invalidHexadecimalTestString, null, EncodingType.Hexadecimal },
                new object[]{ invalidHexadecimalTestString, _hexadecimalEncoder.EncodeToString(invalidSizedIV), EncodingType.Hexadecimal },

                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey1), _base64Encoder.EncodeToString(invalidSizedIV), EncodingType.Base64 },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey1), invalidBase64TestString, EncodingType.Base64 },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey1), null, EncodingType.Base64 },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey1), string.Empty, EncodingType.Base64 },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey1), WhiteSpaceString, EncodingType.Base64 },

                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey1), _hexadecimalEncoder.EncodeToString(invalidSizedIV), EncodingType.Hexadecimal },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey1), invalidHexadecimalTestString, EncodingType.Hexadecimal },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey1), string.Empty, EncodingType.Hexadecimal },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey1), WhiteSpaceString, EncodingType.Hexadecimal },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey1), null, EncodingType.Hexadecimal },

                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey2), _base64Encoder.EncodeToString(invalidSizedIV), EncodingType.Base64 },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey2), invalidBase64TestString, EncodingType.Base64 },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey2), null, EncodingType.Base64 },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey2), string.Empty, EncodingType.Base64 },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey2), WhiteSpaceString, EncodingType.Base64 },

                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey2), _hexadecimalEncoder.EncodeToString(invalidSizedIV), EncodingType.Hexadecimal },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey2), invalidHexadecimalTestString, EncodingType.Hexadecimal },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey2), string.Empty, EncodingType.Hexadecimal },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey2), WhiteSpaceString, EncodingType.Hexadecimal },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey2), null, EncodingType.Hexadecimal },

                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey3), _base64Encoder.EncodeToString(invalidSizedIV), EncodingType.Base64 },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey3), invalidBase64TestString, EncodingType.Base64 },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey3), null, EncodingType.Base64 },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey3), string.Empty, EncodingType.Base64 },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey3), WhiteSpaceString, EncodingType.Base64 },

                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey3), _hexadecimalEncoder.EncodeToString(invalidSizedIV), EncodingType.Hexadecimal },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey3), invalidHexadecimalTestString, EncodingType.Hexadecimal },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey3), string.Empty, EncodingType.Hexadecimal },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey3), WhiteSpaceString, EncodingType.Hexadecimal },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey3), null, EncodingType.Hexadecimal },
            };
        }

        private static IEnumerable<object[]> GetAESAndInvalidInputData() =>
            new List<object[]>()
            {
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), null },
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), Array.Empty<byte>() },

                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), null },
                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), Array.Empty<byte>() },

                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), null },
                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), Array.Empty<byte>() },
            };

        private static IEnumerable<object[]> GetAESAndInvalidInputText() =>
            new List<object[]>()
            {
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), null },
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), string.Empty },
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), WhiteSpaceString },

                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), null },
                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), string.Empty },
                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), WhiteSpaceString },

                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), null },
                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), string.Empty },
                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), WhiteSpaceString },
            };

        private static IEnumerable<object[]> GetAESAndInvalidFilePath()
        {
            var invalidFilePath = Path.Combine(Path.GetTempPath(), $"{Guid.NewGuid()}.txt");

            return new List<object[]>()
            {
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), null },
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), string.Empty },
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), invalidFilePath },

                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), null },
                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), string.Empty },
                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), invalidFilePath },

                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), null },
                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), string.Empty },
                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), invalidFilePath },
            };
        }

        private static IEnumerable<object[]> GetAES() =>
            new List<object[]>()
            {
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits) },
                new object[]{ new AESBase(AESKeySizes.KeySize192Bits) },
                new object[]{ new AESBase(AESKeySizes.KeySize256Bits) },
            };

        private static IEnumerable<object[]> GetAESInputDataOffsetOptionsAndExpecteDecryptedData()
        {
            var data = PlainTestString.ToUTF8Bytes();
            var truncatedToBeginData = data.Take(data.Length / 2).ToArray();
            var truncatedToEndData = data.Skip(data.Length / 2).Take(data.Length / 2).ToArray();
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
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), data, new OffsetOptions(), data },
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), truncatedToBeginData },
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), truncatedToEndData },
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), data },

                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), data, new OffsetOptions(), data },
                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), truncatedToBeginData },
                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), truncatedToEndData },
                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), data },

                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), data, new OffsetOptions(), data },
                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), truncatedToBeginData },
                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), truncatedToEndData },
                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), data },
            };
        }

        private static IEnumerable<object[]> GetAESInputPlainTextOffsetOptionsAndExpectedDecryptedText()
        {
            var text = PlainTestString;
            var truncatedToBeginText = text.Substring(0, text.Length / 2);
            var truncatedToEndText = text.Substring(text.Length / 2, text.Length / 2);

            var additionalTextAtBeginLength = 10;
            var additionalTextAtBegin = new string('a', additionalTextAtBeginLength);
            var additionalTextAtEndLength = 10;
            var additionalTextAtEnd = new string('z', additionalTextAtEndLength);
            var textWithAdditionalTexts = $"{additionalTextAtBegin}{text}{additionalTextAtEnd}";

            return new List<object[]>()
            {
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), text, new OffsetOptions(), text },
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), text, new OffsetOptions(0, truncatedToBeginText.Length), truncatedToBeginText },
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), truncatedToEndText },
                new object[]{ new AESBase(AESKeySizes.KeySize128Bits), textWithAdditionalTexts, new OffsetOptions(additionalTextAtBeginLength, text.Length), text },

                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), text, new OffsetOptions(), text },
                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), text, new OffsetOptions(0, truncatedToBeginText.Length), truncatedToBeginText },
                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), truncatedToEndText },
                new object[]{ new AESBase(AESKeySizes.KeySize192Bits), textWithAdditionalTexts, new OffsetOptions(additionalTextAtBeginLength, text.Length), text },

                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), text, new OffsetOptions(), text },
                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), text, new OffsetOptions(0, truncatedToBeginText.Length), truncatedToBeginText },
                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), truncatedToEndText },
                new object[]{ new AESBase(AESKeySizes.KeySize256Bits), textWithAdditionalTexts, new OffsetOptions(additionalTextAtBeginLength, text.Length), text },
            };
        }

        private static void CreateFileAndWriteText(string filePath, string text) =>
            File.WriteAllText(filePath, text);

        private static string ReadFileText(string filePath) =>
            File.ReadAllText(filePath);
    }
}