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
        private const string PlainTestString = "This is a test string!";
        private const string Base64TestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ=="; // Generated on -> https://www.base64encode.org from the above string
        private const string InvalidBase64TestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ=";
        private readonly byte[] _testByteArray = new byte[]
        {
            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74,
            0x65, 0x73, 0x74, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x21,
        };

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InToBase64String_WhenProvidedNullEmptyOrWhiteSpaceString(string invalidString)
        {
            Func<string> func = () => Base64.ToBase64String(invalidString);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldThrowArgumentException_InToBase64String_WhenProvidedNullOrEmptyByteArray(byte[] invalidByteArray)
        {
            Func<string> func = () => Base64.ToBase64String(invalidByteArray);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.ByteArray_InvalidInputByteArray}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InToString_WhenProvidedNullEmptyOrWhiteSpaceBase64String(string nullEmptyOrWhiteSpaceBase64String)
        {
            Func<string> func = () => Base64.ToString(nullEmptyOrWhiteSpaceBase64String);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        public void ShouldThrowArgumentException_InToString_WhenProvidedInvalidBase64String()
        {
            Func<string> func = () => Base64.ToString(InvalidBase64TestString);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputBase64String}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InToByteArray_WhenProvidedNullEmptyOrWhiteSpaceBase64String(string nullEmptyOrWhiteSpaceBase64String)
        {
            Func<byte[]> func = () => Base64.ToByteArray(nullEmptyOrWhiteSpaceBase64String);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        public void ShouldThrowArgumentException_InToByteArray_WhenProvidedInvalidBase64String()
        {
            Func<byte[]> func = () => Base64.ToByteArray(InvalidBase64TestString);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputBase64String}*");
        }

        [TestMethod]
        public void ShouldEncodeToBase64StringAndMatch_InToBase64String_WhenProvidedPlainString()
        {
            var base64EncodedString = Base64.ToBase64String(PlainTestString);

            base64EncodedString.Should().Be(Base64TestString);
        }

        [TestMethod]
        public void ShouldEncodeToBase64StringAndMatch_InToBase64String_WhenProvidedByteArray()
        {
            var base64EncodedString = Base64.ToBase64String(_testByteArray);

            base64EncodedString.Should().Be(Base64TestString);
        }

        [TestMethod]
        public void ShouldDecodeFromBase64StringAndMatch_InToString()
        {
            var decodedPlainString = Base64.ToString(Base64TestString);

            decodedPlainString.Should().Be(PlainTestString);
        }

        [TestMethod]
        public void ShouldConvertToByteArrayAndMatch_InToByteArray()
        {
            var byteArray = Base64.ToByteArray(Base64TestString);

            byteArray.Should().BeEquivalentTo(_testByteArray);
        }

        [TestMethod]
        [DataRow(Base64TestString, true)]
        [DataRow(InvalidBase64TestString, false)]
        public void ShouldValiteBase64String_InIsValidBase64String(string base64String, bool isValidBase64String)
        {
            var isValid = Base64.IsValidBase64String(base64String);

            isValid.Should().Be(isValidBase64String);
        }
    }
}