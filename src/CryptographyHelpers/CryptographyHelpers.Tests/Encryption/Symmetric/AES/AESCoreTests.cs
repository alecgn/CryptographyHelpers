using CryptographyHelpers.Encryption.Symmetric.AES;
using CryptographyHelpers.Options;
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
    public class AESCoreTests
    {
        private const string PlainStringTest = "This is a test string!";
        private static AESCore _aes;


        [ClassInitialize]
        public static void Initialize(TestContext _)
        {
            _aes = new(AESKeySizes.KeySize128Bits);
        }

        [ClassCleanup]
        public static void Cleanup()
        {
            _aes.Dispose();
        }

        [TestMethod]
        [DynamicData(nameof(GetInvalidKeysAndIVs), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor_WhenProvidedInvalidKeyOrIV(byte[] invalidKey, byte[] invalidIV)
        {
            Action act = () => { AESCore aes = new(invalidKey, invalidIV, CipherMode.CBC, PaddingMode.PKCS7); };

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
        [DataRow(new byte[0])]
        public void ShouldReturnSuccessFalse_InDecrypt_WhenProvidedInvalidInputData(byte[] invalidInputData)
        {
            var aesDecryptionResult = _aes.Decrypt(invalidInputData);

            aesDecryptionResult.Success.Should().BeFalse();
            aesDecryptionResult.Message.Should().Be(MessageStrings.Decryption_InputBytesRequired);
        }

        [TestMethod]
        public void ShouldEncryptAndDecryptDataSucessfully()
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

            aesDecryptionResult.DecryptedData.ToUTF8String().Should().Be(PlainStringTest);
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
        public void ShouldEncryptAndDecryptFileSucessfully()
        {
            var testFilePath = Path.GetTempFileName();
            CreateFileAndWriteText(testFilePath, PlainStringTest);
            var encryptedTestFilePath = Path.ChangeExtension(testFilePath, ".encrypted");

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

            aesDecryptionResult.Success.Should().BeTrue();
            ReadFileText(decryptedTestFilePath).Should().Be(PlainStringTest);
        }

        [TestMethod]
        [DynamicData(nameof(GetStringAndLongOffsetOptions), DynamicDataSourceType.Method)]
        public void ShouldEncryptFileWithLongOffsetOptionsSucessfully(string testString, LongOffsetOptions offsetOptions)
        {
            var testFilePath = Path.GetTempFileName();
            CreateFileAndWriteText(testFilePath, PlainStringTest);
            var encryptedTestFilePath = Path.ChangeExtension(testFilePath, ".encrypted");

            var aesEncryptionResult = _aes.EncryptFile(testFilePath, encryptedTestFilePath, offsetOptions);

            if (!aesEncryptionResult.Success)
            {
                Assert.Fail(aesEncryptionResult.Message);
            }

            var decryptedTestFilePath = Path.ChangeExtension(encryptedTestFilePath, ".decrypted");
            var aesDecryptionResult = _aes.DecryptFile(encryptedTestFilePath, decryptedTestFilePath);

            if (!aesDecryptionResult.Success)
            {
                Assert.Fail(aesDecryptionResult.Message);
            }

            aesDecryptionResult.Success.Should().BeTrue();
            var teste = ReadFileText(decryptedTestFilePath);
            teste.Should().Be(testString);
        }


        private static IEnumerable<object[]> GetInvalidKeysAndIVs()
        {
            // IV has exactly 128 bits, so in this particular case we can use the same random bytes as 128 bits key and IV for our tests purpose
            var random128BitsKeyIV = CryptographyUtils.GenerateRandom128BitsKey();
            var invalidSizeKeyIV = random128BitsKeyIV.Take(random128BitsKeyIV.Length - 1).ToArray();

            return new List<object[]>()
            {
                new object[]{ null, null },
                new object[]{ null, Array.Empty<byte>() },
                new object[]{ null, invalidSizeKeyIV },

                new object[]{ Array.Empty<byte>(), Array.Empty<byte>(), },
                new object[]{ Array.Empty<byte>(), null, },
                new object[]{ Array.Empty<byte>(), invalidSizeKeyIV, },

                new object[]{ invalidSizeKeyIV, invalidSizeKeyIV, },
                new object[]{ invalidSizeKeyIV, null, },
                new object[]{ invalidSizeKeyIV, Array.Empty<byte>(), },
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

        private static void CreateFileAndWriteText(string filePath, string text) =>
            File.WriteAllText(filePath, text);

        private static string ReadFileText(string filePath) =>
            File.ReadAllText(filePath);

        private static IEnumerable<object[]> GetStringAndLongOffsetOptions()
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