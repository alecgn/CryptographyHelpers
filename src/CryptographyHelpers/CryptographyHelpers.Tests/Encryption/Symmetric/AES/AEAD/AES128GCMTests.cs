using CryptographyHelpers.Encryption.Symmetric.AES.AEAD;
using CryptographyHelpers.Resources;
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
        [TestMethod]
        [DynamicData(nameof(GetInvalidKeys), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor1_WhenProvidedInvalidKey(byte[] invalidKey)
        {
            Action act = () => { using var aesGcm = new AES128GCM(invalidKey); };

            act.Should().Throw<ArgumentException>()
                .WithMessage($"{MessageStrings.Cryptography_InvalidAESKey}*");
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
    }
}