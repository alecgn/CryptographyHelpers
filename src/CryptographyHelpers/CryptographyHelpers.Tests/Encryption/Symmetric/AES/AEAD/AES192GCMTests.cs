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
    public class AES192GCMTests
    {
        [TestMethod]
        [DynamicData(nameof(GetInvalidKeys), DynamicDataSourceType.Method)]
        public void ShouldThrowException_InConstructor1_WhenProvidedInvalidKey(byte[] invalidKey)
        {
            Action act = () => { using var aesGcm = new AES192GCM(invalidKey); };

            act.Should().Throw<ArgumentException>()
                .WithMessage($"{MessageStrings.Cryptography_InvalidAESKey}*");
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
    }
}