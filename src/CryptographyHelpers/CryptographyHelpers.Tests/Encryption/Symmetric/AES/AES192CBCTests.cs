using CryptographyHelpers.Encryption.Symmetric.AES;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Utils;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CryptographyHelpers.Tests.Encryption.Symmetric.AES
{
    [TestClass]
    public class AES192CBCTests
    {
        [TestMethod]
        [DynamicData(nameof(GetInvalidKeys), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor1_WhenProvidedInvalidKey(byte[] invalidKey)
        {
            Action act = () => { using var aesGcm = new AES192CBC(invalidKey, CryptographyUtils.GenerateRandomAESIV()); };

            act.Should().Throw<ArgumentException>()
                .WithMessage($"{MessageStrings.Cryptography_InvalidAESKey}*");
        }

        [TestMethod]
        [DynamicData(nameof(GetInvalidIVs), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor1_WhenProvidedInvalidIV(byte[] invalidIV)
        {
            Action act = () => { using var aesGcm = new AES192CBC(CryptographyUtils.GenerateRandom192BitsKey(), invalidIV); };

            act.Should().Throw<ArgumentException>()
                .WithMessage($"{MessageStrings.Cryptography_InvalidAESIV}*");
        }


        private static IEnumerable<object[]> GetInvalidKeys()
        {
            var random192BitsKey = CryptographyUtils.GenerateRandom192BitsKey();
            var invalidSizedKey = random192BitsKey.Take(random192BitsKey.Length - 1).ToArray();

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
    }
}