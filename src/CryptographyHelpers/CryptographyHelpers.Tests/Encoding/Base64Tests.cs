using CryptographyHelpers.Encoding;
using CryptographyHelpers.Resources;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace CryptographyHelpers.Tests.Encoding
{
    [TestClass]
    public class Base64Tests
    {
        private readonly Base64 _base64 = new();
        private const string _invalidBase64TestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ=";
        private const string _base64TestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ==";
        private const string _plainTestString = "This is a test string!";

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InToBase64String_WhenProvidedNullEmptyOrWhiteSpaceString(string invalidString)
        {
            Func<string> act = () => _base64.ToBase64String(invalidString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldThrowArgumentException_InToBase64String_WhenProvidedNullOrEmptyByteArray(byte[] invalidByteArray)
        {
            Func<string> act = () => _base64.ToBase64String(invalidByteArray);

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
            Func<string> act = () => _base64.ToString(invalidString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        public void ShouldThrowArgumentException_InToString_WhenProvidedInvalidBase64String()
        {
            Func<string> act = () => _base64.ToString(_invalidBase64TestString);

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
            Func<byte[]> act = () => _base64.ToByteArray(invalidString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        public void ShouldThrowArgumentException_InToByteArray_WhenProvidedInvalidBase64String()
        {
            Func<byte[]> act = () => _base64.ToByteArray(_invalidBase64TestString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputBase64String}*");
        }

        [TestMethod]
        [DataRow(_invalidBase64TestString, false)]
        [DataRow(_base64TestString, true)]
        public void ShouldValiteBase64String_InIsValidBase64String(string base64String, bool isValidBase64String)
        {
            var isValid = _base64.IsValidBase64String(base64String);

            isValid.Should().Be(isValidBase64String);
        }

        [TestMethod]
        public void ShouldMatchBase64String_InToBase64String()
        {
            var base64String = _base64.ToBase64String(_plainTestString);

            base64String.Should().Be(_base64TestString);
        }
    }
}