using CryptographyHelpers.Encryption.Symmetric.AES;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CryptographyHelpers.Tests.Encryption.Symmetric.AES
{
    [TestClass]
    public class AES128CBCTests
    {
        private static readonly IBase64Encoder _base64Encoder = InternalServiceLocator.Instance.GetService<IBase64Encoder>();
        private static readonly IHexadecimalEncoder _hexadecimalEncoder = InternalServiceLocator.Instance.GetService<IHexadecimalEncoder>();

        [TestMethod]
        [DynamicData(nameof(GetInvalidKeys), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor2_WhenProvidedInvalidKey(byte[] invalidKey)
        {
            Action act = () => { using var aesGcm = new AES128CBC(invalidKey, CryptographyUtils.GenerateRandomAESIV()); };

            act.Should().Throw<ArgumentException>()
                .WithMessage($"{MessageStrings.Cryptography_InvalidAESKey}*");
        }

        [TestMethod]
        [DynamicData(nameof(GetInvalidIVs), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor2_WhenProvidedInvalidIV(byte[] invalidIV)
        {
            Action act = () => { using var aesGcm = new AES128CBC(CryptographyUtils.GenerateRandom128BitsKey(), invalidIV); };

            act.Should().Throw<ArgumentException>()
                .WithMessage($"{MessageStrings.Cryptography_InvalidAESIV}*");
        }

        [TestMethod]
        [DynamicData(nameof(GetInvalidEncodedKeys), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor3_WhenProvidedInvalidEncodedKey(string invalidEncodedKey, EncodingType encodingType)
        {
            var validIV = CryptographyUtils.GenerateRandomAESIV();
            var validEncodedIV = encodingType switch
            {
                EncodingType.Base64 => _base64Encoder.EncodeToString(validIV),
                EncodingType.Hexadecimal => _hexadecimalEncoder.EncodeToString(validIV),
                _ => throw new InvalidOperationException($@"Unexpected enum value ""{encodingType}"" of type {typeof(EncodingType)}."),
            };

            Action act = () => { using var aesGcm = new AES128CBC(invalidEncodedKey, validEncodedIV, encodingType); };

            act.Should().Throw<Exception>();
        }

        [TestMethod]
        [DynamicData(nameof(GetInvalidEncodedIVs), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor3_WhenProvidedInvalidEncodedIV(string invalidEncodedIV, EncodingType encodingType)
        {
            var valid128BitsKey = CryptographyUtils.GenerateRandom128BitsKey();
            var validEncoded128BitsKey = encodingType switch
            {
                EncodingType.Base64 => _base64Encoder.EncodeToString(valid128BitsKey),
                EncodingType.Hexadecimal => _hexadecimalEncoder.EncodeToString(valid128BitsKey),
                _ => throw new InvalidOperationException($@"Unexpected enum value ""{encodingType}"" of type {typeof(EncodingType)}."),
            };

            Action act = () => { using var aesGcm = new AES128CBC(validEncoded128BitsKey, invalidEncodedIV, encodingType); };

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

        private static IEnumerable<object[]> GetInvalidIVs()
        {
            var randomAESIV = CryptographyUtils.GenerateRandomAESIV();
            var invalidSizedIV = randomAESIV.Take(randomAESIV.Length - 1).ToArray();

            return new List<object[]>()
            {
                new object[]{ null },
                new object[]{ Array.Empty<byte>() },
                new object[]{ invalidSizedIV },
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

        private static IEnumerable<object[]> GetInvalidEncodedIVs()
        {
            var randomIV = CryptographyUtils.GenerateRandomAESIV();
            var invalidSizedIV = randomIV.Take(randomIV.Length - 1).ToArray();
            var invalidSizedBase64EncodedIV = _base64Encoder.EncodeToString(invalidSizedIV);
            var invalidBase64EncodedIV = invalidSizedBase64EncodedIV[1..];
            var invalidSizedHexadecimalEncodedIV = _hexadecimalEncoder.EncodeToString(invalidSizedIV);
            var invalidHexadecimalEncodedIV = invalidSizedHexadecimalEncodedIV[1..];

            return new List<object[]>()
            {
                new object[]{ invalidSizedBase64EncodedIV, EncodingType.Base64 },
                new object[]{ invalidBase64EncodedIV, EncodingType.Base64 },
                new object[]{ invalidSizedHexadecimalEncodedIV, EncodingType.Hexadecimal },
                new object[]{ invalidHexadecimalEncodedIV, EncodingType.Hexadecimal },
            };
        }
    }
}