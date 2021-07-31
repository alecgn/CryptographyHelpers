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
    public class AES128GCMTests
    {
        private static readonly IBase64Encoder _base64Encoder = InternalServiceLocator.Instance.GetService<IBase64Encoder>();
        private static readonly IHexadecimalEncoder _hexadecimalEncoder = InternalServiceLocator.Instance.GetService<IHexadecimalEncoder>();

        [TestMethod]
        [DynamicData(nameof(GetInvalidKeys), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor2_WhenProvidedInvalidKey(byte[] invalidKey)
        {
            Action act = () => { using var aesGcm = new AES128GCM(invalidKey); };

            act.Should().Throw<ArgumentException>()
                .WithMessage($"{MessageStrings.Cryptography_InvalidAESKey}*");
        }

        [TestMethod]
        [DynamicData(nameof(GetInvalidEncodedKeys), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor3_WhenProvidedInvalidEncodedKey(string invalidEncodedKey, EncodingType encodingType)
        {
            Action act = () => { using var aesGcm = new AES128GCM(invalidEncodedKey, encodingType); };

            act.Should().Throw<Exception>();
        }


        private static IEnumerable<object[]> GetInvalidKeys()
        {
            var random128BitsKey = CryptographyUtils.GenerateRandom128BitsKey();
            var invalidSizedKey = random128BitsKey.Take(random128BitsKey.Length - 1).ToArray();

            return new List<object[]>()
            {
                new object[]{ null },
                new object[]{ Array.Empty<byte>() },
                new object[]{ invalidSizedKey },
            };
        }

        private static IEnumerable<object[]> GetInvalidEncodedKeys()
        {
            var random128BitsKey = CryptographyUtils.GenerateRandom128BitsKey();
            var invalidSizedKey = random128BitsKey.Take(random128BitsKey.Length - 1).ToArray();
            var invalidSizedBase64EncodedKey = _base64Encoder.EncodeToString(invalidSizedKey);
            var invalidBase64EncodedKey = invalidSizedBase64EncodedKey[1..];
            var invalidSizedHexadecimalEncodedKey = _hexadecimalEncoder.EncodeToString(invalidSizedKey);
            var invalidHexadecimalEncodedKey = invalidSizedHexadecimalEncodedKey[1..];

            return new List<object[]>()
            {
                new object[]{ invalidSizedBase64EncodedKey, EncodingType.Base64 },
                new object[]{ invalidBase64EncodedKey, EncodingType.Base64 },
                new object[]{ invalidSizedHexadecimalEncodedKey, EncodingType.Hexadecimal },
                new object[]{ invalidHexadecimalEncodedKey, EncodingType.Hexadecimal },
            };
        }
    }
}