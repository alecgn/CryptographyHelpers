using CryptographyHelpers.Encoding;
using CryptographyHelpers.Resources;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;

namespace CryptographyHelpers.Tests.Encoding
{
    [TestClass]
    public class Base64Tests
    {
        private const string _invalidBase64String = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ=";
        private const string _testPlainString = "This is a test string!";
        private const string _testBase64String = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ==";

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InToBase64String_WhenProvidedNullEmptyOrWhiteSpaceString(string invalidString)
        {
            Func<string> act = () => Base64.ToBase64String(invalidString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldThrowArgumentException_InToBase64String_WhenProvidedNullOrEmptyByteArray(byte[] invalidByteArray)
        {
            Func<string> act = () => Base64.ToBase64String(invalidByteArray);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.ByteArray_InvalidInputByteArray}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InToString_WhenProvidedNullEmptyOrWhiteSpaceString(string invalidString)
        {
            Func<string> act = () => Base64.ToString(invalidString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        public void ShouldThrowArgumentException_InToString_WhenProvidedInvalidBase64String()
        {
            Func<string> act = () => Base64.ToString(_invalidBase64String);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputBase64String}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InToByteArray_WhenProvidedNullEmptyOrWhiteSpaceString(string invalidString)
        {
            Func<byte[]> act = () => Base64.ToByteArray(invalidString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        public void ShouldThrowArgumentException_InToByteArray_WhenProvidedInvalidBase64String()
        {
            Func<byte[]> act = () => Base64.ToByteArray(_invalidBase64String);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputBase64String}*");
        }

        [TestMethod]
        [DataRow(_invalidBase64String, false)]
        [DataRow(_testBase64String, true)]
        public void ShouldValiteBase64String_InIsValidBase64String(string base64String, bool isValidBase64String)
        {
            var isValid = Base64.IsValidBase64String(base64String);

            isValid.Should().Be(isValidBase64String);
        }

        [TestMethod]
        public void ShouldMatchBase64String_InToBase64String()
        {
            var base64String = Base64.ToBase64String(_testPlainString);

            base64String.Should().Be(_testBase64String);
        }
    }
}
