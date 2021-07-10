using Bogus;
using CryptographyHelpers.Encryption.Symmetric.AES;
using CryptographyHelpers.Encryption.Symmetric.AES.AEAD;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CryptographyHelpers.Tests.Encryption.Symmetric.AES.AEAD
{
    [TestClass]
    public class AESGCMCoreTests
    {
        private const string PlainTestString = "This is a test string!";
        private static readonly IBase64 _base64Encoder = InternalServiceLocator.Instance.GetService<IBase64>();
        private static readonly IHexadecimal _hexadecimalEncoder = InternalServiceLocator.Instance.GetService<IHexadecimal>();


        [TestMethod]
        [DynamicData(nameof(GetInvalidKeys), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor1_WhenProvidedInvalidKey(byte[] invalidKey)
        {
            Action act = () => { using var aesGcm = new AESGCMCore(invalidKey); };

            act.Should().Throw<Exception>();
        }

        [TestMethod]
        [DynamicData(nameof(GetInvalidEncodedKeys), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor2_WhenProvidedInvalidEncodedKey(string invalidEncodedKey, EncodingType encodingType)
        {
            Action act = () => { using var aesGcm = new AESGCMCore(invalidEncodedKey, encodingType); };

            act.Should().Throw<Exception>();
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InEncrypt_WhenProvidedInvalidInputData(AESGCMCore aesGcm, byte[] invalidInputData)
        {
            AESGCMEncryptionResult aesGcmEncryptionResult;

            using (aesGcm)
            {
                aesGcmEncryptionResult = aesGcm.Encrypt(invalidInputData);
            }

            aesGcmEncryptionResult.Success.Should().BeFalse();
            aesGcmEncryptionResult.Message.Should().Be(MessageStrings.Encryption_InputBytesRequired);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidInputText), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InEncryptText_WhenProvidedInvalidInputText(AESGCMCore aesGcm, string invalidInputText)
        {
            AESGCMTextEncryptionResult aesGcmTextEncryptionResult;

            using (aesGcm)
            {
                aesGcmTextEncryptionResult = aesGcm.EncryptText(invalidInputText);
            }

            aesGcmTextEncryptionResult.Success.Should().BeFalse();
            aesGcmTextEncryptionResult.Message.Should().Be(MessageStrings.Encryption_InputTextRequired);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InDecrypt_WhenProvidedInvalidInputData(AESGCMCore aesGcm, byte[] invalidInputData)
        {
            AESGCMDecryptionResult aesGcmDecryptionResult;

            using (aesGcm)
            {
                aesGcmDecryptionResult = aesGcm.Decrypt(invalidInputData, null, null);
            }

            aesGcmDecryptionResult.Success.Should().BeFalse();
            aesGcmDecryptionResult.Message.Should().Be(MessageStrings.Decryption_InputBytesRequired);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidNoncesAndTags), DynamicDataSourceType.Method)]
        public void ShouldReturnFalse_InDecrypt_WhenProvidedInvalidNonceOrTag(AESGCMCore aesGcm, byte[] invalidNonce, byte[] invalidTag)
        {
            AESGCMDecryptionResult aesGcmDecryptionResult;
            var randomBytes = CryptographyUtils.GenerateRandomBytes(PlainTestString.Length);

            using (aesGcm)
            {
                aesGcmDecryptionResult = aesGcm.Decrypt(randomBytes, invalidNonce, invalidTag);
            }

            aesGcmDecryptionResult.Success.Should().BeFalse();
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidInputText), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InDecryptText_WhenProvidedInvalidInputText(AESGCMCore aesGcm, string invalidInputText)
        {
            AESGCMTextDecryptionResult aesGcmTextDecryptionResult;

            using (aesGcm)
            {
                aesGcmTextDecryptionResult = aesGcm.DecryptText(invalidInputText, null, null);
            }

            aesGcmTextDecryptionResult.Success.Should().BeFalse();
            aesGcmTextDecryptionResult.Message.Should().Be(MessageStrings.Decryption_InputTextRequired);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidEncodedNoncesAndTags), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InDecryptText_WhenProvidedInvalidEncodedNonceOrTag(AESGCMCore aesGcm, string invalidEncodedNonce, string invalidEncodedTag)
        {
            AESGCMDecryptionResult aesGcmTextDecryptionResult;

            using (aesGcm)
            {
                aesGcmTextDecryptionResult = aesGcm.DecryptText(new Faker().Lorem.Sentence(), invalidEncodedNonce, invalidEncodedTag);
            }

            aesGcmTextDecryptionResult.Success.Should().BeFalse();
        }

        [TestMethod]
        [DynamicData(nameof(GetAESInputDataOffsetOptionsAssociatedDataAndExpecteDecryptedData), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptDataSucessfully_WithAndWithoutOffsetOptionsAndAssociatedData_InEncrypt_And_WithoutOffsetOptions_InDecrypt(AESGCMCore aesGcm, byte[] inputData, OffsetOptions offsetOptions, byte[] associatedData, byte[] expectedDecryptedData)
        {
            AESGCMEncryptionResult aesGcmEncryptionResult;
            AESGCMDecryptionResult aesGcmDecryptionResult;

            using (aesGcm)
            {
                aesGcmEncryptionResult = aesGcm.Encrypt(inputData, offsetOptions, associatedData);

                if (!aesGcmEncryptionResult.Success)
                {
                    Assert.Fail(aesGcmEncryptionResult.Message);
                }

                aesGcmDecryptionResult = aesGcm.Decrypt(
                    aesGcmEncryptionResult.EncryptedData,
                    aesGcmEncryptionResult.Nonce,
                    aesGcmEncryptionResult.Tag,
                    null,
                    aesGcmEncryptionResult.AssociatedData);

                if (!aesGcmDecryptionResult.Success)
                {
                    Assert.Fail(aesGcmDecryptionResult.Message);
                }
            }

            aesGcmDecryptionResult.DecryptedData.Should().BeEquivalentTo(expectedDecryptedData);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndAssociatedData), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptDataSucessfully_WithAndWithoutAssociatedData_And_WithOffsetOptions_InDecrypt_And_WithoutOffsetOptions_InEncrypt(AESGCMCore aesGcm, byte[] associatedData)
        {
            AESGCMEncryptionResult aesGcmEncryptionResult;
            AESGCMDecryptionResult aesGcmDecryptionResult;
            var dataBytes = PlainTestString.ToUTF8Bytes();

            using (aesGcm)
            {
                aesGcmEncryptionResult = aesGcm.Encrypt(dataBytes, null, associatedData);

                if (!aesGcmEncryptionResult.Success)
                {
                    Assert.Fail(aesGcmEncryptionResult.Message);
                }

                var additionalDataAtBeginLenght = 10;
                var additionalDataAtBegin = CryptographyUtils.GenerateRandomBytes(additionalDataAtBeginLenght);
                var additionalDataAtEndLenght = 10;
                var additionalDataAtEnd = CryptographyUtils.GenerateRandomBytes(additionalDataAtEndLenght);
                var encryptedDataWithAdditionalData = new byte[additionalDataAtBeginLenght + aesGcmEncryptionResult.EncryptedData.Length + additionalDataAtEndLenght];
                Array.Copy(additionalDataAtBegin, 0, encryptedDataWithAdditionalData, 0, additionalDataAtBeginLenght);
                Array.Copy(aesGcmEncryptionResult.EncryptedData, 0, encryptedDataWithAdditionalData, additionalDataAtBeginLenght, aesGcmEncryptionResult.EncryptedData.Length);
                Array.Copy(additionalDataAtEnd, 0, encryptedDataWithAdditionalData, additionalDataAtBeginLenght + aesGcmEncryptionResult.EncryptedData.Length, additionalDataAtEndLenght);

                aesGcmDecryptionResult = aesGcm.Decrypt(encryptedDataWithAdditionalData, aesGcmEncryptionResult.Nonce, aesGcmEncryptionResult.Tag, new OffsetOptions(additionalDataAtBeginLenght, aesGcmEncryptionResult.EncryptedData.Length), associatedData);
            }

            if (!aesGcmDecryptionResult.Success)
            {
                Assert.Fail(aesGcmDecryptionResult.Message);
            }

            aesGcmDecryptionResult.DecryptedData.Should().BeEquivalentTo(dataBytes);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESInputPlainTextOffsetOptionsAssociatedDataTextAndExpecteDecryptedText), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptTextSucessfully_WithAndWithoutOffsetOptionsAndAssociatedDataText_InEncryptText_And_WithoutOffsetOptions_InDecryptText(AESGCMCore aesGcm, string inputPlainText, OffsetOptions offsetOptions, string associatedDataText, string expectedDecryptedText)
        {
            AESGCMTextEncryptionResult aesGcmTextEncryptionResult;
            AESGCMTextDecryptionResult aesGcmTextDecryptionResult;

            using (aesGcm)
            {
                aesGcmTextEncryptionResult = aesGcm.EncryptText(inputPlainText, offsetOptions, associatedDataText);

                if (!aesGcmTextEncryptionResult.Success)
                {
                    Assert.Fail(aesGcmTextEncryptionResult.Message);
                }

                aesGcmTextDecryptionResult = aesGcm.DecryptText(
                    aesGcmTextEncryptionResult.EncodedEncryptedText,
                    aesGcmTextEncryptionResult.EncodedNonce,
                    aesGcmTextEncryptionResult.EncodedTag,
                    null,
                    aesGcmTextEncryptionResult.AssociatedDataText);

                if (!aesGcmTextDecryptionResult.Success)
                {
                    Assert.Fail(aesGcmTextDecryptionResult.Message);
                }
            }

            aesGcmTextDecryptionResult.DecryptedText.Should().Be(expectedDecryptedText);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndAssociatedDataText), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptTextSucessfully_WithAndWithoutAssociatedDataText_And_WithOffsetOptions_InDecryptText_And_WithoutOffsetOptions_InEncryptText(AESGCMCore aesGcm, string associatedDataText)
        {
            AESGCMTextEncryptionResult aesGcmTextEncryptionResult;
            AESGCMTextDecryptionResult aesGcmTextDecryptionResult;
            var text = PlainTestString;

            using (aesGcm)
            {
                aesGcmTextEncryptionResult = aesGcm.EncryptText(text, null, associatedDataText);

                if (!aesGcmTextEncryptionResult.Success)
                {
                    Assert.Fail(aesGcmTextEncryptionResult.Message);
                }

                var additionalTextAtBeginLenght = 10;
                var additionalTextAtBegin = new string('a', additionalTextAtBeginLenght);
                var additionalTextAtEndLenght = 10;
                var additionalTextAtEnd = new string('z', additionalTextAtEndLenght);
                var encryptedTextWithAdditionalText = $"{additionalTextAtBegin}{aesGcmTextEncryptionResult.EncodedEncryptedText}{additionalTextAtEnd}";
                aesGcmTextDecryptionResult = aesGcm.DecryptText(encryptedTextWithAdditionalText, aesGcmTextEncryptionResult.EncodedNonce, aesGcmTextEncryptionResult.EncodedTag, new OffsetOptions(additionalTextAtBeginLenght, aesGcmTextEncryptionResult.EncodedEncryptedText.Length), associatedDataText);
            }

            if (!aesGcmTextDecryptionResult.Success)
            {
                Assert.Fail(aesGcmTextDecryptionResult.Message);
            }

            aesGcmTextDecryptionResult.DecryptedText.Should().Be(text);
        }


        private static IEnumerable<object[]> GetInvalidKeys()
        {
            var random128BitsKey = CryptographyUtils.GenerateRandom128BitsKey();
            var random192BitsKey = CryptographyUtils.GenerateRandom192BitsKey();
            var random256BitsKey = CryptographyUtils.GenerateRandom256BitsKey();
            var invalidSizedKey1 = random128BitsKey.Take(random128BitsKey.Length - 1).ToArray();
            var invalidSizedKey2 = random192BitsKey.Take(random192BitsKey.Length - 1).ToArray();
            var invalidSizedKey3 = random256BitsKey.Take(random256BitsKey.Length - 1).ToArray();

            return new List<object[]>()
            {
                new object[]{ null },
                new object[]{ Array.Empty<byte>() },
                new object[]{ invalidSizedKey1 },
                new object[]{ invalidSizedKey2 },
                new object[]{ invalidSizedKey3 },
            };
        }

        private static IEnumerable<object[]> GetInvalidEncodedKeys()
        {
            var random128BitsKey = CryptographyUtils.GenerateRandom128BitsKey();
            var random192BitsKey = CryptographyUtils.GenerateRandom192BitsKey();
            var random256BitsKey = CryptographyUtils.GenerateRandom256BitsKey();
            var invalidSizedKey1 = random128BitsKey.Take(random128BitsKey.Length - 1).ToArray();
            var invalidSizedKey2 = random192BitsKey.Take(random192BitsKey.Length - 1).ToArray();
            var invalidSizedKey3 = random256BitsKey.Take(random256BitsKey.Length - 1).ToArray();
            string invalidBase64TestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ=";
            string invalidHexadecimalTestString = "546869732069732061207465737420737472696E672G";

            return new List<object[]>()
            {
                new object[]{ null, EncodingType.Base64 },
                new object[]{ null, EncodingType.Hexadecimal },
                new object[]{ "", EncodingType.Base64 },
                new object[]{ "", EncodingType.Hexadecimal },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey1), EncodingType.Base64 },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey1), EncodingType.Hexadecimal },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey2), EncodingType.Base64 },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey2), EncodingType.Hexadecimal },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey3), EncodingType.Base64 },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey3), EncodingType.Hexadecimal },
                new object[]{ invalidBase64TestString, EncodingType.Base64 },
                new object[]{ invalidHexadecimalTestString, EncodingType.Hexadecimal },
            };
        }

        private static IEnumerable<object[]> GetAESAndInvalidInputData() =>
            new List<object[]>()
            {
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), Array.Empty<byte>() },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), Array.Empty<byte>() },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), Array.Empty<byte>() },
            };

        private static IEnumerable<object[]> GetAESAndInvalidInputText() =>
            new List<object[]>()
            {
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), "   " },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), "   " },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), "   " },
            };

        private static IEnumerable<object[]> GetAESAndInvalidNoncesAndTags()
        {
            const int invalidNonceOrTagLength = 100;
            var randomBytes = CryptographyUtils.GenerateRandomBytes(invalidNonceOrTagLength);

            return new List<object[]>()
            {
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), null, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), null, Array.Empty<byte>() },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), null, randomBytes },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), Array.Empty<byte>(), null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), Array.Empty<byte>(), Array.Empty<byte>() },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), Array.Empty<byte>(), randomBytes },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), randomBytes, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), randomBytes, Array.Empty<byte>() },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), randomBytes, randomBytes },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), null, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), null, Array.Empty<byte>() },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), null, randomBytes },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), Array.Empty<byte>(), null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), Array.Empty<byte>(), Array.Empty<byte>() },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), Array.Empty<byte>(), randomBytes },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), randomBytes, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), randomBytes, Array.Empty<byte>() },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), randomBytes, randomBytes },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), null, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), null, Array.Empty<byte>() },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), null, randomBytes },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), Array.Empty<byte>(), null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), Array.Empty<byte>(), Array.Empty<byte>() },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), Array.Empty<byte>(), randomBytes },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), randomBytes, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), randomBytes, Array.Empty<byte>() },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), randomBytes, randomBytes },
            };
        }

        private static IEnumerable<object[]> GetAESAndInvalidEncodedNoncesAndTags()
        {
            const int invalidNonceOrTagLength = 100;
            var randomBytes = CryptographyUtils.GenerateRandomBytes(invalidNonceOrTagLength);
            var invalidHexadecimalEncodedNonceOrTag = _hexadecimalEncoder.EncodeToString(randomBytes).Substring(1);
            var invalidBase64EncodedNonceOrTag = _base64Encoder.EncodeToString(randomBytes).Substring(1);

            return new List<object[]>()
            {
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), null, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), null, "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), null, "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), null, invalidHexadecimalEncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), "", "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), "", null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), "", "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), "", invalidHexadecimalEncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), "   ", "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), "   ", null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), "   ", "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), "   ", invalidHexadecimalEncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedNonceOrTag, invalidHexadecimalEncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedNonceOrTag, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedNonceOrTag, "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedNonceOrTag, "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), null, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), null, "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), null, "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), null, invalidBase64EncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), "", "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), "", null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), "", "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), "", invalidBase64EncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), "   ", "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), "   ", null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), "   ", "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), "   ", invalidBase64EncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), invalidBase64EncodedNonceOrTag, invalidBase64EncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), invalidBase64EncodedNonceOrTag, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), invalidBase64EncodedNonceOrTag, "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits, EncodingType.Base64), invalidBase64EncodedNonceOrTag, "   " },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), null, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), null, "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), null, "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), null, invalidHexadecimalEncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), "", "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), "", null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), "", "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), "", invalidHexadecimalEncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), "   ", "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), "   ", null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), "   ", "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), "   ", invalidHexadecimalEncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedNonceOrTag, invalidHexadecimalEncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedNonceOrTag, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedNonceOrTag, "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedNonceOrTag, "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), null, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), null, "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), null, "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), null, invalidBase64EncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), "", "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), "", null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), "", "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), "", invalidBase64EncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), "   ", "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), "   ", null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), "   ", "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), "   ", invalidBase64EncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), invalidBase64EncodedNonceOrTag, invalidBase64EncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), invalidBase64EncodedNonceOrTag, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), invalidBase64EncodedNonceOrTag, "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits, EncodingType.Base64), invalidBase64EncodedNonceOrTag, "   " },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), null, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), null, "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), null, "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), null, invalidHexadecimalEncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), "", "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), "", null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), "", "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), "", invalidHexadecimalEncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), "   ", "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), "   ", null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), "   ", "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), "   ", invalidHexadecimalEncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedNonceOrTag, invalidHexadecimalEncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedNonceOrTag, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedNonceOrTag, "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedNonceOrTag, "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), null, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), null, "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), null, "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), null, invalidBase64EncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), "", "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), "", null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), "", "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), "", invalidBase64EncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), "   ", "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), "   ", null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), "   ", "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), "   ", invalidBase64EncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), invalidBase64EncodedNonceOrTag, invalidBase64EncodedNonceOrTag },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), invalidBase64EncodedNonceOrTag, null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), invalidBase64EncodedNonceOrTag, "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits, EncodingType.Base64), invalidBase64EncodedNonceOrTag, "   " },
            };
        }

        private static IEnumerable<object[]> GetAESInputDataOffsetOptionsAssociatedDataAndExpecteDecryptedData()
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
            var associatedData = Guid.NewGuid().ToString().ToUTF8Bytes();

            return new List<object[]>()
            {
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), data, new OffsetOptions(), null, data },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), null, truncatedToBeginData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), null, truncatedToEndData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), null, data },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), data, new OffsetOptions(), Array.Empty<byte>(), data },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), Array.Empty<byte>(), truncatedToBeginData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), Array.Empty<byte>(), truncatedToEndData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), Array.Empty<byte>(), data },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), data, new OffsetOptions(), associatedData, data },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), associatedData, truncatedToBeginData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), associatedData, truncatedToEndData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), associatedData, data },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), data, new OffsetOptions(), null, data },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), null, truncatedToBeginData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), null, truncatedToEndData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), null, data },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), data, new OffsetOptions(), Array.Empty<byte>(), data },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), Array.Empty<byte>(), truncatedToBeginData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), Array.Empty<byte>(), truncatedToEndData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), Array.Empty<byte>(), data },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), data, new OffsetOptions(), associatedData, data },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), associatedData, truncatedToBeginData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), associatedData, truncatedToEndData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), associatedData, data },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), data, new OffsetOptions(), null, data },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), null, truncatedToBeginData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), null, truncatedToEndData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), null, data },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), data, new OffsetOptions(), Array.Empty<byte>(), data },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), Array.Empty<byte>(), truncatedToBeginData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), Array.Empty<byte>(), truncatedToEndData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), Array.Empty<byte>(), data },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), data, new OffsetOptions(), associatedData, data },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), associatedData, truncatedToBeginData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), associatedData, truncatedToEndData },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), associatedData, data },
            };
        }

        private static IEnumerable<object[]> GetAESAndAssociatedData() =>
            new List<object[]>()
            {
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), Array.Empty<byte>() },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), Guid.NewGuid().ToString().ToUTF8Bytes() },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), Array.Empty<byte>() },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), Guid.NewGuid().ToString().ToUTF8Bytes() },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), Array.Empty<byte>() },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), Guid.NewGuid().ToString().ToUTF8Bytes() },
            };

        private static IEnumerable<object[]> GetAESInputPlainTextOffsetOptionsAssociatedDataTextAndExpecteDecryptedText()
        {
            var text = PlainTestString;
            var truncatedToBeginText = text.Substring(0, PlainTestString.Length / 2);
            var truncatedToEndText = text.Substring(PlainTestString.Length / 2, PlainTestString.Length / 2);
            var additionalTextAtBeginLength = 10;
            var additionalTextAtBegin = new string('a', additionalTextAtBeginLength);
            var additionalTextAtEndLength = 10;
            var additionalTextAtEnd = new string('z', additionalTextAtEndLength);
            var textWithAdditionalText = $"{additionalTextAtBegin}{text}{additionalTextAtEnd}";
            var associatedDataText = Guid.NewGuid().ToString();

            return new List<object[]>()
            {
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), text, new OffsetOptions(), null, text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), text, new OffsetOptions(0, truncatedToBeginText.Length), null, truncatedToBeginText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), null, truncatedToEndText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), textWithAdditionalText, new OffsetOptions(additionalTextAtBeginLength, text.Length), null, text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), text, new OffsetOptions(), "", text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), text, new OffsetOptions(0, truncatedToBeginText.Length), "", truncatedToBeginText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), "", truncatedToEndText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), textWithAdditionalText, new OffsetOptions(additionalTextAtBeginLength, text.Length), "", text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), text, new OffsetOptions(), "   ", text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), text, new OffsetOptions(0, truncatedToBeginText.Length), "   ", truncatedToBeginText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), "   ", truncatedToEndText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), textWithAdditionalText, new OffsetOptions(additionalTextAtBeginLength, text.Length), "   ", text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), text, new OffsetOptions(), associatedDataText, text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), text, new OffsetOptions(0, truncatedToBeginText.Length), associatedDataText, truncatedToBeginText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), associatedDataText, truncatedToEndText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), textWithAdditionalText, new OffsetOptions(additionalTextAtBeginLength, text.Length), associatedDataText, text },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), text, new OffsetOptions(), null, text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), text, new OffsetOptions(0, truncatedToBeginText.Length), null, truncatedToBeginText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), null, truncatedToEndText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), textWithAdditionalText, new OffsetOptions(additionalTextAtBeginLength, text.Length), null, text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), text, new OffsetOptions(), "", text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), text, new OffsetOptions(0, truncatedToBeginText.Length), "", truncatedToBeginText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), "", truncatedToEndText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), textWithAdditionalText, new OffsetOptions(additionalTextAtBeginLength, text.Length), "", text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), text, new OffsetOptions(), "   ", text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), text, new OffsetOptions(0, truncatedToBeginText.Length), "   ", truncatedToBeginText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), "   ", truncatedToEndText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), textWithAdditionalText, new OffsetOptions(additionalTextAtBeginLength, text.Length), "   ", text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), text, new OffsetOptions(), associatedDataText, text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), text, new OffsetOptions(0, truncatedToBeginText.Length), associatedDataText, truncatedToBeginText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), associatedDataText, truncatedToEndText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), textWithAdditionalText, new OffsetOptions(additionalTextAtBeginLength, text.Length), associatedDataText, text },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), text, new OffsetOptions(), null, text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), text, new OffsetOptions(0, truncatedToBeginText.Length), null, truncatedToBeginText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), null, truncatedToEndText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), textWithAdditionalText, new OffsetOptions(additionalTextAtBeginLength, text.Length), null, text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), text, new OffsetOptions(), "", text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), text, new OffsetOptions(0, truncatedToBeginText.Length), "", truncatedToBeginText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), "", truncatedToEndText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), textWithAdditionalText, new OffsetOptions(additionalTextAtBeginLength, text.Length), "", text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), text, new OffsetOptions(), "   ", text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), text, new OffsetOptions(0, truncatedToBeginText.Length), "   ", truncatedToBeginText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), "   ", truncatedToEndText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), textWithAdditionalText, new OffsetOptions(additionalTextAtBeginLength, text.Length), "   ", text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), text, new OffsetOptions(), associatedDataText, text },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), text, new OffsetOptions(0, truncatedToBeginText.Length), associatedDataText, truncatedToBeginText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), text, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), associatedDataText, truncatedToEndText },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), textWithAdditionalText, new OffsetOptions(additionalTextAtBeginLength, text.Length), associatedDataText, text },
            };
        }

        private static IEnumerable<object[]> GetAESAndAssociatedDataText() =>
            new List<object[]>()
            {
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize128Bits), Guid.NewGuid().ToString() },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize192Bits), Guid.NewGuid().ToString() },

                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), null },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), "" },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), "   " },
                new object[]{ new AESGCMCore(AESKeySizes.KeySize256Bits), Guid.NewGuid().ToString() },
            };
    }
}