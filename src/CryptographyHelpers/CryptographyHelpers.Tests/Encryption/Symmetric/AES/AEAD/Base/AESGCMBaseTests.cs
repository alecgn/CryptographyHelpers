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
using System.Security.Cryptography;

namespace CryptographyHelpers.Tests.Encryption.Symmetric.AES.AEAD
{
    [TestClass]
    public class AESGCMBaseTests
    {
        private const string WhiteSpaceString = " ";
        private const string PlainTestString = "This is a test string!";
        private static readonly IBase64Encoder _base64Encoder = InternalServiceLocator.Instance.GetService<IBase64Encoder>();
        private static readonly IHexadecimalEncoder _hexadecimalEncoder = InternalServiceLocator.Instance.GetService<IHexadecimalEncoder>();


        [TestMethod]
        [DynamicData(nameof(GetInvalidKeys), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor1_WhenProvidedInvalidKey(byte[] invalidKey)
        {
            Action act = () => { using var aesGcm = new AESGCMBase(invalidKey); };

            act.Should().Throw<Exception>();
        }

        [TestMethod]
        [DynamicData(nameof(GetInvalidEncodedKeys), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor2_WhenProvidedInvalidEncodedKey(string invalidEncodedKey, EncodingType encodingType)
        {
            Action act = () => { using var aesGcm = new AESGCMBase(invalidEncodedKey, encodingType); };

            act.Should().Throw<Exception>();
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InEncrypt_WhenProvidedInvalidInputData(AESGCMBase aesGcm, byte[] invalidInputData)
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
        public void ShouldReturnSuccessFalse_InEncryptText_WhenProvidedInvalidInputText(AESGCMBase aesGcm, string invalidInputText)
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
        public void ShouldReturnSuccessFalse_InDecrypt_WhenProvidedInvalidInputData(AESGCMBase aesGcm, byte[] invalidInputData)
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
        [DynamicData(nameof(GetAESAndInvalidNonces), DynamicDataSourceType.Method)]
        public void ShouldReturnFalse_InDecrypt_WhenProvidedInvalidNonce(AESGCMBase aesGcm, byte[] invalidNonce)
        {
            AESGCMDecryptionResult aesGcmDecryptionResult;
            var randomBytes = CryptographyUtils.GenerateRandomBytes(PlainTestString.Length);
            var tag = CryptographyUtils.GenerateRandomBytes(AesGcm.TagByteSizes.MaxSize);

            using (aesGcm)
            {
                aesGcmDecryptionResult = aesGcm.Decrypt(randomBytes, invalidNonce, tag);
            }

            aesGcmDecryptionResult.Success.Should().BeFalse();
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidTags), DynamicDataSourceType.Method)]
        public void ShouldReturnFalse_InDecrypt_WhenProvidedInvalidTag(AESGCMBase aesGcm, byte[] invalidTag)
        {
            AESGCMDecryptionResult aesGcmDecryptionResult;
            var randomBytes = CryptographyUtils.GenerateRandomBytes(PlainTestString.Length);
            var nonce = CryptographyUtils.GenerateRandomBytes(AesGcm.NonceByteSizes.MaxSize);

            using (aesGcm)
            {
                aesGcmDecryptionResult = aesGcm.Decrypt(randomBytes, nonce, invalidTag);
            }

            aesGcmDecryptionResult.Success.Should().BeFalse();
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidInputText), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InDecryptText_WhenProvidedInvalidInputText(AESGCMBase aesGcm, string invalidInputText)
        {
            AESGCMTextDecryptionResult aesGcmTextDecryptionResult;

            using (aesGcm)
            {
                aesGcmTextDecryptionResult = aesGcm.DecryptText(invalidInputText);
            }

            aesGcmTextDecryptionResult.Success.Should().BeFalse();
            aesGcmTextDecryptionResult.Message.Should().Be(MessageStrings.Decryption_InputTextRequired);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidEncodedNonces), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InDecryptText_WhenProvidedInvalidEncodedNonce(AESGCMBase aesGcm, string invalidEncodedNonce)
        {
            var tag = CryptographyUtils.GenerateRandomBytes(AesGcm.TagByteSizes.MaxSize);
            var encodedTag = aesGcm.EncodingType == EncodingType.Base64
                ? _base64Encoder.EncodeToString(tag)
                : _hexadecimalEncoder.EncodeToString(tag);
            AESGCMDecryptionResult aesGcmTextDecryptionResult;

            using (aesGcm)
            {
                aesGcmTextDecryptionResult = aesGcm.DecryptText(
                    new Faker().Lorem.Sentence(),
                    hasMetadataInInputEncryptedText: false,
                    invalidEncodedNonce,
                    encodedTag);
            }

            aesGcmTextDecryptionResult.Success.Should().BeFalse();
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidEncodedTags), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InDecryptText_WhenProvidedInvalidEncodedTag(AESGCMBase aesGcm, string invalidEncodedTag)
        {
            var nonce = CryptographyUtils.GenerateRandomBytes(AesGcm.NonceByteSizes.MaxSize);
            var encodedNonce = aesGcm.EncodingType == EncodingType.Base64
                ? _base64Encoder.EncodeToString(nonce)
                : _hexadecimalEncoder.EncodeToString(nonce);
            AESGCMDecryptionResult aesGcmTextDecryptionResult;

            using (aesGcm)
            {
                aesGcmTextDecryptionResult = aesGcm.DecryptText(
                    new Faker().Lorem.Sentence(),
                    hasMetadataInInputEncryptedText: false,
                    encodedNonce, 
                    invalidEncodedTag);
            }

            aesGcmTextDecryptionResult.Success.Should().BeFalse();
        }

        [TestMethod]
        [DynamicData(nameof(GetAESInputDataOffsetOptionsAssociatedDataAndExpecteDecryptedData), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptDataSucessfully_WithAndWithoutOffsetOptionsAndAssociatedData_InEncrypt_And_WithoutOffsetOptions_InDecrypt(AESGCMBase aesGcm, byte[] inputData, OffsetOptions offsetOptions, byte[] associatedData, byte[] expectedDecryptedData)
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
        public void ShouldEncryptAndDecryptDataSucessfully_WithAndWithoutAssociatedData_And_WithOffsetOptions_InDecrypt_And_WithoutOffsetOptions_InEncrypt(AESGCMBase aesGcm, byte[] associatedData)
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
        [DynamicData(nameof(GetAESInputPlainTextAppendInfoToOutputOffsetOptionsAssociatedDataTextAndExpecteDecryptedText), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptTextSucessfully_WithAndWithoutOffsetOptionsAndAssociatedDataText_InEncryptText_And_WithoutOffsetOptions_InDecryptText(AESGCMBase aesGcm, string inputPlainText, bool appendDataToOutput, OffsetOptions offsetOptions, string associatedDataText, string expectedDecryptedText)
        {
            AESGCMTextEncryptionResult aesGcmTextEncryptionResult;
            AESGCMTextDecryptionResult aesGcmTextDecryptionResult;

            using (aesGcm)
            {
                aesGcmTextEncryptionResult = aesGcm.EncryptText(
                    inputPlainText,
                    addMetadataToOutputEncryptedText: appendDataToOutput,
                    offsetOptions,
                    associatedDataText);

                if (!aesGcmTextEncryptionResult.Success)
                {
                    Assert.Fail(aesGcmTextEncryptionResult.Message);
                }

                aesGcmTextDecryptionResult = aesGcm.DecryptText(
                    aesGcmTextEncryptionResult.EncodedEncryptedText,
                    hasMetadataInInputEncryptedText: appendDataToOutput,
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
        [DynamicData(nameof(GetAESAppendInfoToOutputAndAssociatedDataText), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptTextSucessfully_WithAndWithoutAssociatedDataText_And_WithOffsetOptions_InDecryptText_And_WithoutOffsetOptions_InEncryptText(AESGCMBase aesGcm, bool metadataFlag, string associatedDataText)
        {
            AESGCMTextEncryptionResult aesGcmTextEncryptionResult;
            AESGCMTextDecryptionResult aesGcmTextDecryptionResult;
            var text = PlainTestString;

            using (aesGcm)
            {
                aesGcmTextEncryptionResult = aesGcm.EncryptText(
                    text,
                    addMetadataToOutputEncryptedText: metadataFlag,
                    null,
                    associatedDataText);

                if (!aesGcmTextEncryptionResult.Success)
                {
                    Assert.Fail(aesGcmTextEncryptionResult.Message);
                }

                var additionalTextAtBeginLenght = 10;
                var additionalTextAtBegin = new string('a', additionalTextAtBeginLenght);
                var additionalTextAtEndLenght = 10;
                var additionalTextAtEnd = new string('z', additionalTextAtEndLenght);
                var encryptedTextWithAdditionalText = $"{additionalTextAtBegin}{aesGcmTextEncryptionResult.EncodedEncryptedText}{additionalTextAtEnd}";
                aesGcmTextDecryptionResult = aesGcm.DecryptText(
                    encryptedTextWithAdditionalText,
                    hasMetadataInInputEncryptedText: metadataFlag,
                    aesGcmTextEncryptionResult.EncodedNonce,
                    aesGcmTextEncryptionResult.EncodedTag,
                    new OffsetOptions(additionalTextAtBeginLenght, aesGcmTextEncryptionResult.EncodedEncryptedText.Length),
                    associatedDataText);
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
                new object[]{ string.Empty, EncodingType.Base64 },
                new object[]{ string.Empty, EncodingType.Hexadecimal },
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
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), Array.Empty<byte>() },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), Array.Empty<byte>() },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), Array.Empty<byte>() },
            };

        private static IEnumerable<object[]> GetAESAndInvalidInputText() =>
            new List<object[]>()
            {
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), WhiteSpaceString },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), WhiteSpaceString },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), WhiteSpaceString },
            };

        private static IEnumerable<object[]> GetAESAndInvalidNonces()
        {
            var invalidNonceSize = AesGcm.NonceByteSizes.MaxSize + 1;
            var invalidRandomNonceBytes = CryptographyUtils.GenerateRandomBytes(invalidNonceSize);

            return new List<object[]>()
            {
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), Array.Empty<byte>() },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), invalidRandomNonceBytes },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), Array.Empty<byte>() },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), invalidRandomNonceBytes },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), Array.Empty<byte>() },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), invalidRandomNonceBytes },
            };
        }

        private static IEnumerable<object[]> GetAESAndInvalidTags()
        {
            var invalidTagSize = AesGcm.TagByteSizes.MaxSize + 1;
            var invalidRandomTagBytes = CryptographyUtils.GenerateRandomBytes(invalidTagSize);

            return new List<object[]>()
            {
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), Array.Empty<byte>() },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), invalidRandomTagBytes },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), Array.Empty<byte>() },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), invalidRandomTagBytes },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), Array.Empty<byte>() },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), invalidRandomTagBytes },
            };
        }

        private static IEnumerable<object[]> GetAESAndInvalidEncodedNonces()
        {
            var invalidRandomNonceBytes = CryptographyUtils.GenerateRandomBytes(AesGcm.NonceByteSizes.MaxSize + 1);
            var invalidSizedHexadecimalEncodedNonce = _hexadecimalEncoder.EncodeToString(invalidRandomNonceBytes); // valid hexadecimal but invalid nonce size
            var invalidHexadecimalEncodedNonce = _hexadecimalEncoder.EncodeToString(invalidRandomNonceBytes)[1..]; // invalid hexadecimal
            var invalidSizedBase64EncodedNonce = _base64Encoder.EncodeToString(invalidRandomNonceBytes); // valid base64 but invalid nonce size
            var invalidBase64EncodedNonce = _base64Encoder.EncodeToString(invalidRandomNonceBytes)[1..]; // invalid base64

            return new List<object[]>()
            {
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), invalidSizedHexadecimalEncodedNonce },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedNonce },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Base64), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Base64), string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Base64), WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Base64), invalidSizedBase64EncodedNonce },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Base64), invalidBase64EncodedNonce },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), invalidSizedHexadecimalEncodedNonce },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedNonce },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Base64), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Base64), string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Base64), WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Base64), invalidSizedBase64EncodedNonce },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Base64), invalidBase64EncodedNonce },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), invalidSizedHexadecimalEncodedNonce },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedNonce },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Base64), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Base64), string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Base64), WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Base64), invalidSizedBase64EncodedNonce },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Base64), invalidBase64EncodedNonce },
            };
        }

        private static IEnumerable<object[]> GetAESAndInvalidEncodedTags()
        {
            var invalidRandomTagBytes = CryptographyUtils.GenerateRandomBytes(AesGcm.TagByteSizes.MaxSize + 1);
            var invalidSizedHexadecimalEncodedTag = _hexadecimalEncoder.EncodeToString(invalidRandomTagBytes); // valid hexadecimal but invalid nonce size
            var invalidHexadecimalEncodedTag = _hexadecimalEncoder.EncodeToString(invalidRandomTagBytes)[1..]; // invalid hexadecimal
            var invalidSizedBase64EncodedTag = _base64Encoder.EncodeToString(invalidRandomTagBytes); // valid base64 but invalid nonce size
            var invalidBase64EncodedTag = _base64Encoder.EncodeToString(invalidRandomTagBytes)[1..]; // invalid base64

            return new List<object[]>()
            {
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), invalidSizedHexadecimalEncodedTag },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedTag },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Base64), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Base64), string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Base64), WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Base64), invalidSizedBase64EncodedTag },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits, EncodingType.Base64), invalidBase64EncodedTag },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), invalidSizedHexadecimalEncodedTag },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedTag },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Base64), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Base64), string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Base64), WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Base64), invalidSizedBase64EncodedTag },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits, EncodingType.Base64), invalidBase64EncodedTag },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), invalidSizedHexadecimalEncodedTag },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Hexadecimal), invalidHexadecimalEncodedTag },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Base64), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Base64), string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Base64), WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Base64), invalidSizedBase64EncodedTag },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits, EncodingType.Base64), invalidBase64EncodedTag },
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
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), data, new OffsetOptions(), null, data },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), null, truncatedToBeginData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), null, truncatedToEndData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), null, data },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), data, new OffsetOptions(), Array.Empty<byte>(), data },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), Array.Empty<byte>(), truncatedToBeginData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), Array.Empty<byte>(), truncatedToEndData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), Array.Empty<byte>(), data },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), data, new OffsetOptions(), associatedData, data },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), associatedData, truncatedToBeginData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), associatedData, truncatedToEndData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), associatedData, data },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), data, new OffsetOptions(), null, data },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), null, truncatedToBeginData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), null, truncatedToEndData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), null, data },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), data, new OffsetOptions(), Array.Empty<byte>(), data },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), Array.Empty<byte>(), truncatedToBeginData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), Array.Empty<byte>(), truncatedToEndData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), Array.Empty<byte>(), data },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), data, new OffsetOptions(), associatedData, data },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), associatedData, truncatedToBeginData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), associatedData, truncatedToEndData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), associatedData, data },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), data, new OffsetOptions(), null, data },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), null, truncatedToBeginData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), null, truncatedToEndData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), null, data },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), data, new OffsetOptions(), Array.Empty<byte>(), data },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), Array.Empty<byte>(), truncatedToBeginData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), Array.Empty<byte>(), truncatedToEndData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), Array.Empty<byte>(), data },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), data, new OffsetOptions(), associatedData, data },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), data, new OffsetOptions(0, truncatedToBeginData.Length), associatedData, truncatedToBeginData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), data, new OffsetOptions(truncatedToEndData.Length, truncatedToEndData.Length), associatedData, truncatedToEndData },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), dataWithAdditionalData, new OffsetOptions(additionalDataAtBeginLength, data.Length), associatedData, data },
            };
        }

        private static IEnumerable<object[]> GetAESAndAssociatedData() =>
            new List<object[]>()
            {
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), Array.Empty<byte>() },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), Guid.NewGuid().ToString().ToUTF8Bytes() },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), Array.Empty<byte>() },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), Guid.NewGuid().ToString().ToUTF8Bytes() },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), Array.Empty<byte>() },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), Guid.NewGuid().ToString().ToUTF8Bytes() },
            };

        private static IEnumerable<object[]> GetAESInputPlainTextAppendInfoToOutputOffsetOptionsAssociatedDataTextAndExpecteDecryptedText()
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
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, false, new OffsetOptions(), null, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, true, new OffsetOptions(), null, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, false, new OffsetOptions(0, truncatedToBeginText.Length), null, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, true, new OffsetOptions(0, truncatedToBeginText.Length), null, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, false, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), null, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, true, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), null, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), textWithAdditionalText, false, new OffsetOptions(additionalTextAtBeginLength, text.Length), null, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), textWithAdditionalText, true, new OffsetOptions(additionalTextAtBeginLength, text.Length), null, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, false, new OffsetOptions(), string.Empty, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, true, new OffsetOptions(), string.Empty, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, false, new OffsetOptions(0, truncatedToBeginText.Length), string.Empty, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, true, new OffsetOptions(0, truncatedToBeginText.Length), string.Empty, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, false, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), string.Empty, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, true, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), string.Empty, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), textWithAdditionalText, false, new OffsetOptions(additionalTextAtBeginLength, text.Length), string.Empty, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), textWithAdditionalText, true, new OffsetOptions(additionalTextAtBeginLength, text.Length), string.Empty, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, false, new OffsetOptions(), WhiteSpaceString, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, true, new OffsetOptions(), WhiteSpaceString, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, false, new OffsetOptions(0, truncatedToBeginText.Length), WhiteSpaceString, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, true, new OffsetOptions(0, truncatedToBeginText.Length), WhiteSpaceString, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, false, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), WhiteSpaceString, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, true, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), WhiteSpaceString, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), textWithAdditionalText, false, new OffsetOptions(additionalTextAtBeginLength, text.Length), WhiteSpaceString, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), textWithAdditionalText, true, new OffsetOptions(additionalTextAtBeginLength, text.Length), WhiteSpaceString, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, false, new OffsetOptions(), associatedDataText, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, true, new OffsetOptions(), associatedDataText, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, false, new OffsetOptions(0, truncatedToBeginText.Length), associatedDataText, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, true, new OffsetOptions(0, truncatedToBeginText.Length), associatedDataText, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, false, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), associatedDataText, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), text, true, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), associatedDataText, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), textWithAdditionalText, false, new OffsetOptions(additionalTextAtBeginLength, text.Length), associatedDataText, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), textWithAdditionalText, true, new OffsetOptions(additionalTextAtBeginLength, text.Length), associatedDataText, text },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, false, new OffsetOptions(), null, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, true, new OffsetOptions(), null, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, false, new OffsetOptions(0, truncatedToBeginText.Length), null, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, true, new OffsetOptions(0, truncatedToBeginText.Length), null, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, false, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), null, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, true, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), null, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), textWithAdditionalText, false, new OffsetOptions(additionalTextAtBeginLength, text.Length), null, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), textWithAdditionalText, true, new OffsetOptions(additionalTextAtBeginLength, text.Length), null, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, false, new OffsetOptions(), string.Empty, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, true, new OffsetOptions(), string.Empty, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, false, new OffsetOptions(0, truncatedToBeginText.Length), string.Empty, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, true, new OffsetOptions(0, truncatedToBeginText.Length), string.Empty, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, false, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), string.Empty, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, true, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), string.Empty, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), textWithAdditionalText, false, new OffsetOptions(additionalTextAtBeginLength, text.Length), string.Empty, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), textWithAdditionalText, true, new OffsetOptions(additionalTextAtBeginLength, text.Length), string.Empty, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, false, new OffsetOptions(), WhiteSpaceString, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, true, new OffsetOptions(), WhiteSpaceString, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, false, new OffsetOptions(0, truncatedToBeginText.Length), WhiteSpaceString, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, true, new OffsetOptions(0, truncatedToBeginText.Length), WhiteSpaceString, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, false, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), WhiteSpaceString, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, true, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), WhiteSpaceString, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), textWithAdditionalText, false, new OffsetOptions(additionalTextAtBeginLength, text.Length), WhiteSpaceString, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), textWithAdditionalText, true, new OffsetOptions(additionalTextAtBeginLength, text.Length), WhiteSpaceString, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, false, new OffsetOptions(), associatedDataText, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, true, new OffsetOptions(), associatedDataText, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, false, new OffsetOptions(0, truncatedToBeginText.Length), associatedDataText, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, true, new OffsetOptions(0, truncatedToBeginText.Length), associatedDataText, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, false, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), associatedDataText, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), text, true, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), associatedDataText, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), textWithAdditionalText, false, new OffsetOptions(additionalTextAtBeginLength, text.Length), associatedDataText, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), textWithAdditionalText, true, new OffsetOptions(additionalTextAtBeginLength, text.Length), associatedDataText, text },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, false, new OffsetOptions(), null, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, true, new OffsetOptions(), null, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, false, new OffsetOptions(0, truncatedToBeginText.Length), null, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, true, new OffsetOptions(0, truncatedToBeginText.Length), null, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, false, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), null, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, true, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), null, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), textWithAdditionalText, false, new OffsetOptions(additionalTextAtBeginLength, text.Length), null, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), textWithAdditionalText, true, new OffsetOptions(additionalTextAtBeginLength, text.Length), null, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, false, new OffsetOptions(), string.Empty, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, true, new OffsetOptions(), string.Empty, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, false, new OffsetOptions(0, truncatedToBeginText.Length), string.Empty, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, true, new OffsetOptions(0, truncatedToBeginText.Length), string.Empty, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, false, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), string.Empty, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, true, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), string.Empty, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), textWithAdditionalText, false, new OffsetOptions(additionalTextAtBeginLength, text.Length), string.Empty, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), textWithAdditionalText, true, new OffsetOptions(additionalTextAtBeginLength, text.Length), string.Empty, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, false, new OffsetOptions(), WhiteSpaceString, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, true, new OffsetOptions(), WhiteSpaceString, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, false, new OffsetOptions(0, truncatedToBeginText.Length), WhiteSpaceString, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, true, new OffsetOptions(0, truncatedToBeginText.Length), WhiteSpaceString, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, false, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), WhiteSpaceString, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, true, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), WhiteSpaceString, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), textWithAdditionalText, false, new OffsetOptions(additionalTextAtBeginLength, text.Length), WhiteSpaceString, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), textWithAdditionalText, true, new OffsetOptions(additionalTextAtBeginLength, text.Length), WhiteSpaceString, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, false, new OffsetOptions(), associatedDataText, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, true, new OffsetOptions(), associatedDataText, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, false, new OffsetOptions(0, truncatedToBeginText.Length), associatedDataText, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, true, new OffsetOptions(0, truncatedToBeginText.Length), associatedDataText, truncatedToBeginText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, false, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), associatedDataText, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), text, true, new OffsetOptions(truncatedToEndText.Length, truncatedToEndText.Length), associatedDataText, truncatedToEndText },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), textWithAdditionalText, false, new OffsetOptions(additionalTextAtBeginLength, text.Length), associatedDataText, text },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), textWithAdditionalText, true, new OffsetOptions(additionalTextAtBeginLength, text.Length), associatedDataText, text },
            };
        }

        private static IEnumerable<object[]> GetAESAppendInfoToOutputAndAssociatedDataText() =>
            new List<object[]>()
            {
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), false, null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), true, null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), false, string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), true, string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), false, WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), true, WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), false, Guid.NewGuid().ToString() },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize128Bits), true, Guid.NewGuid().ToString() },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), false, null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), true, null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), false, string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), true, string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), false, WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), true, WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), false, Guid.NewGuid().ToString() },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize192Bits), true, Guid.NewGuid().ToString() },

                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), false, null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), true, null },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), false, string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), true, string.Empty },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), false, WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), true, WhiteSpaceString },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), false, Guid.NewGuid().ToString() },
                new object[]{ new AESGCMBase(AESKeySizes.KeySize256Bits), true, Guid.NewGuid().ToString() },
            };
    }
}