using CryptographyHelpers.Encryption.Symmetric.AES;
using CryptographyHelpers.Encryption.Symmetric.AES.AEAD;
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
        private const string PlainStringTest = "This is a test string!";
        private static AESGCMCore _aesGcm;

        [ClassInitialize]
        public static void Initialize(TestContext _)
        {
            _aesGcm = new(AESKeySizes.KeySize128Bits);
        }

        [ClassCleanup]
        public static void Cleanup()
        {
            _aesGcm.Dispose();
        }


        [TestMethod]
        [DynamicData(nameof(GetInvalidKeys), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor_WhenProvidedInvalidKey(byte[] invalidKey)
        {
            Action act = () => { AESGCMCore aesGcm = new(invalidKey); };

            act.Should().Throw<Exception>();
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldReturnSuccessFalse_InEncrypt_WhenProvidedInvalidInputData(byte[] invalidInputData)
        {
            var aesGcmEncryptionResult = _aesGcm.Encrypt(invalidInputData);

            aesGcmEncryptionResult.Success.Should().BeFalse();
            aesGcmEncryptionResult.Message.Should().Be(MessageStrings.Encryption_InputBytesRequired);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldReturnSuccessFalse_InDecrypt_WhenProvidedInvalidInputData(byte[] invalidInputData)
        {
            var aesGcmDecryptionResult = _aesGcm.Decrypt(invalidInputData, null, null);

            aesGcmDecryptionResult.Success.Should().BeFalse();
            aesGcmDecryptionResult.Message.Should().Be(MessageStrings.Decryption_InputBytesRequired);
        }

        [TestMethod]
        [DynamicData(nameof(GetInvalidNoncesAndTags), DynamicDataSourceType.Method)]
        public void ShouldReturnFalse_InDecrypt_WhenProvidedInvalidNonceOrTag(byte[] nonce, byte[] tag)
        {
            var aesGcDecryptionResult = _aesGcm.Decrypt(CryptographyUtils.GenerateRandomBytes(PlainStringTest.Length), nonce, tag);

            aesGcDecryptionResult.Success.Should().BeFalse();
        }

        [TestMethod]
        [DynamicData(nameof(GetAssociatedData), DynamicDataSourceType.Method)]
        public void ShouldEncryptAndDecryptDataSucessfully_WithAndWithoutAssociatedData(string associatedData)
        {
            var dataBytes = PlainStringTest.ToUTF8Bytes();
            var associatedDataBytes = associatedData?.ToUTF8Bytes();

            var aesGcmEncryptionResult = _aesGcm.Encrypt(dataBytes, associatedDataBytes);

            if (!aesGcmEncryptionResult.Success)
            {
                Assert.Fail(aesGcmEncryptionResult.Message);
            }

            var aesGcmDecryptionResult = _aesGcm.Decrypt(
                aesGcmEncryptionResult.EncryptedData, 
                aesGcmEncryptionResult.Nonce, 
                aesGcmEncryptionResult.Tag, 
                aesGcmEncryptionResult.AssociatedData);

            if (!aesGcmDecryptionResult.Success)
            {
                Assert.Fail(aesGcmDecryptionResult.Message);
            }

            aesGcmDecryptionResult.DecryptedData.ToUTF8String().Should().Be(PlainStringTest);
        }


        private static IEnumerable<object[]> GetInvalidKeys()
        {
            var random128BitsKey = CryptographyUtils.GenerateRandom128BitsKey();
            var invalidSizeKey = random128BitsKey.Take(random128BitsKey.Length - 1).ToArray();

            return new List<object[]>()
            {
                new object[]{ null },
                new object[]{ Array.Empty<byte>() },
                new object[]{ invalidSizeKey }
            };
        }

        private static IEnumerable<object[]> GetInvalidNoncesAndTags()
        {
            const int invalidNonceOrTagLength = 100;
            var randomBytes = CryptographyUtils.GenerateRandomBytes(invalidNonceOrTagLength);

            return new List<object[]>()
            {
                new object[]{ null, null },
                new object[]{ null, Array.Empty<byte>() },
                new object[]{ null, randomBytes },

                new object[]{ Array.Empty<byte>(), Array.Empty<byte>() },
                new object[]{ Array.Empty<byte>(), null },
                new object[]{ Array.Empty<byte>(), randomBytes },

                new object[]{ randomBytes, randomBytes },
                new object[]{ randomBytes, null },
                new object[]{ randomBytes, Array.Empty<byte>() },
            };
        }

        private static IEnumerable<object[]> GetAssociatedData() =>
            new List<object[]>()
            {
                new object[]{ null },
                new object[]{ Guid.NewGuid().ToString() },
            };
    }
}