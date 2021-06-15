using CryptographyHelpers.Extensions;
using CryptographyHelpers.KeyDerivation;
using FluentAssertions;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace CryptographyHelpers.Tests
{
    [TestClass]
    public class ExtensionsTests
    {
        [TestMethod]
        public void ShouldNotCastInvalidEnumValue()
        {
            var hmacAlgorithmTypeMD5 = PseudoRandomFunction.HMACMD5;
            Func<KeyDerivationPrf> func = () => hmacAlgorithmTypeMD5.Cast<PseudoRandomFunction, KeyDerivationPrf>();

            // KeyDerivationPrf enum does not contain HMACMD5 as a value
            func.Should().ThrowExactly<InvalidCastException>();
        }

        [TestMethod]
        public void ShouldCastValidEnumValue()
        {
            var hmacAlgorithmTypeSHA1 = PseudoRandomFunction.HMACSHA1;
            var result = hmacAlgorithmTypeSHA1.Cast<PseudoRandomFunction, KeyDerivationPrf>();

            // KeyDerivationPrf enum contains HMACSHA1 as a value
            result.Should().Be(KeyDerivationPrf.HMACSHA1);
        }
    }
}