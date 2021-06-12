//using CryptographyHelpers.Extensions;
//using CryptographyHelpers.HMAC.Enums;
//using FluentAssertions;
//using Microsoft.AspNetCore.Cryptography.KeyDerivation;
//using Microsoft.VisualStudio.TestTools.UnitTesting;
//using System;

//namespace CryptographyHelpers.Tests.Encoding
//{
//    [TestClass]
//    public class ExtensionsTests
//    {
//        [TestMethod]
//        public void ShouldNotCastInvalidEnumValue()
//        {
//            var hmacAlgorithmTypeMD5 = HMACAlgorithmType.HMACSHA1;
//            Func<KeyDerivationPrf> func = () => hmacAlgorithmTypeMD5.Cast<HMACAlgorithmType, KeyDerivationPrf>();

//            func.Should().ThrowExactly<InvalidCastException>();
//        }
//    }
//}
