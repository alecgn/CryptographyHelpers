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
        //private static AESGCMCore _aesGcm;

        //[ClassInitialize]
        //public static void Initialize(TestContext _)
        //{
        //    _aesGcm = new(AESKeySizes.KeySize128Bits);
        //}

        //[ClassCleanup]
        //public static void Cleanup()
        //{
        //    _aesGcm.Dispose();
        //}


        [TestMethod]
        [DynamicData(nameof(GetInvalidKeys), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor_WhenProvidedInvalidKey(byte[] invalidKey)
        {
            Action act = () => { var aesGcm = new AESGCMCore(invalidKey); };

            act.Should().Throw<Exception>();
        }

        [TestMethod]
        [DynamicData(nameof(GetInvalidEncodedKeys), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor_WhenProvidedInvalidEncodedKey(string invalidEncodedKey, EncodingType encodingType)
        {
            Action act = () => { var aesGcm = new AESGCMCore(invalidEncodedKey, encodingType); };

            act.Should().Throw<Exception>();
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InEncrypt_WhenProvidedInvalidInputData(AESGCMCore aesGcm, byte[] invalidInputData)
        {
            var aesGcmEncryptionResult = aesGcm.Encrypt(invalidInputData);

            aesGcmEncryptionResult.Success.Should().BeFalse();
            aesGcmEncryptionResult.Message.Should().Be(MessageStrings.Encryption_InputBytesRequired);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndAssociatedData), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptDataSucessfully_WithAndWithoutAssociatedData(AESGCMCore aesGcm, byte[] associatedData)
        {
            var dataBytes = PlainTestString.ToUTF8Bytes();
            var aesGcmEncryptionResult = aesGcm.Encrypt(dataBytes, null, associatedData);

            if (!aesGcmEncryptionResult.Success)
            {
                Assert.Fail(aesGcmEncryptionResult.Message);
            }

            var aesGcmDecryptionResult = aesGcm.Decrypt(
                aesGcmEncryptionResult.EncryptedData,
                aesGcmEncryptionResult.Nonce,
                aesGcmEncryptionResult.Tag,
                null,
                aesGcmEncryptionResult.AssociatedData);

            if (!aesGcmDecryptionResult.Success)
            {
                Assert.Fail(aesGcmDecryptionResult.Message);
            }

            aesGcmDecryptionResult.DecryptedData.ToUTF8String().Should().Be(PlainTestString);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndAssociatedData), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptTextSucessfully_WithAndWithoutAssociatedData(AESGCMCore aesGcm, string associatedData)
        {
            var aesGcmTextEncryptionResult = aesGcm.EncryptText(PlainTestString, null, associatedData);

            if (!aesGcmTextEncryptionResult.Success)
            {
                Assert.Fail(aesGcmTextEncryptionResult.Message);
            }

            var aesGcmTextDecryptionResult = aesGcm.DecryptText(
                aesGcmTextEncryptionResult.EncodedEncryptedText,
                aesGcmTextEncryptionResult.EncodedNonce,
                aesGcmTextEncryptionResult.EncodedTag,
                null,
                aesGcmTextEncryptionResult.AssociatedDataString);

            if (!aesGcmTextDecryptionResult.Success)
            {
                Assert.Fail(aesGcmTextDecryptionResult.Message);
            }

            aesGcmTextDecryptionResult.DecryptedText.Should().Be(PlainTestString);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InDecrypt_WhenProvidedInvalidInputData(AESGCMCore aesGcm, byte[] invalidInputData)
        {
            var aesGcmDecryptionResult = aesGcm.Decrypt(invalidInputData, null, null);

            aesGcmDecryptionResult.Success.Should().BeFalse();
            aesGcmDecryptionResult.Message.Should().Be(MessageStrings.Decryption_InputBytesRequired);
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndInvalidNoncesAndTags), DynamicDataSourceType.Method)]
        public void ShouldReturnFalse_InDecrypt_WhenProvidedInvalidNonceOrTag(AESGCMCore aesGcm, byte[] nonce, byte[] tag)
        {
            var aesGcDecryptionResult = aesGcm.Decrypt(CryptographyUtils.GenerateRandomBytes(PlainTestString.Length), nonce, tag);

            aesGcDecryptionResult.Success.Should().BeFalse();
        }

        [TestMethod]
        [DynamicData(nameof(GetAESAndAssociatedData), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptDataSucessfully_WithAndWithoutAssociatedData(AESGCMCore aesGcm, string associatedData)
        {
            var dataBytes = PlainTestString.ToUTF8Bytes();
            var associatedDataBytes = associatedData?.ToUTF8Bytes();

            var aesGcmEncryptionResult = aesGcm.Encrypt(dataBytes, null, associatedDataBytes);

            if (!aesGcmEncryptionResult.Success)
            {
                Assert.Fail(aesGcmEncryptionResult.Message);
            }

            var aesGcmDecryptionResult = aesGcm.Decrypt(
                aesGcmEncryptionResult.EncryptedData, 
                aesGcmEncryptionResult.Nonce, 
                aesGcmEncryptionResult.Tag, 
                null,
                aesGcmEncryptionResult.AssociatedData);

            if (!aesGcmDecryptionResult.Success)
            {
                Assert.Fail(aesGcmDecryptionResult.Message);
            }

            aesGcmDecryptionResult.DecryptedData.ToUTF8String().Should().Be(PlainTestString);
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

                new object[]{ null, EncodingType.Base64 },
                new object[]{ null, EncodingType.Hexadecimal },
                new object[]{ "", EncodingType.Base64 },
                new object[]{ "", EncodingType.Hexadecimal },
                new object[]{ _base64Encoder.EncodeToString(invalidSizedKey2), EncodingType.Base64 },
                new object[]{ _hexadecimalEncoder.EncodeToString(invalidSizedKey2), EncodingType.Hexadecimal },
                

                new object[]{ null, EncodingType.Base64 },
                new object[]{ null, EncodingType.Hexadecimal },
                new object[]{ "", EncodingType.Base64 },
                new object[]{ "", EncodingType.Hexadecimal },
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
    }
}