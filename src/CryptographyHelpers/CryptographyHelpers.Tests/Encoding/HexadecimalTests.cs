using CryptographyHelpers.Encoding;
using CryptographyHelpers.Resources;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace CryptographyHelpers.Tests.Encoding
{
    [TestClass]
    public class HexadecimalTests
    {
        private const string _plainTestString = "This is a test string!";
        private readonly byte[] _testByteArray = new byte[]
        {
            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 
            0x65, 0x73, 0x74, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x21, 
        };
        private const string _uppercaseHexadecimalTestStringWithoutPrefix = "546869732069732061207465737420737472696E6721";
        private const string _uppercaseHexadecimalTestStringWithPrefix = "0x546869732069732061207465737420737472696E6721";
        private const string _lowercaseHexadecimalTestStringWithoutPrefix = "546869732069732061207465737420737472696e6721";
        private const string _lowercaseHexadecimalTestStringWithPrefix = "0x546869732069732061207465737420737472696e6721";
        private const string _invalidHexadecimalTestString = "546869732069732061207465737420737472696E672G";

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InToHexadecimalString_WhenProvidedNullEmptyOrWhiteSpaceString(string invalidString)
        {
            Func<string> act = () => Hexadecimal.ToHexadecimalString(invalidString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldThrowArgumentException_InToHexadecimalString_WhenProvidedNullOrEmptyByteArray(byte[] invalidByteArray)
        {
            Func<string> act = () => Hexadecimal.ToHexadecimalString(invalidByteArray);

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
            Func<string> act = () => Hexadecimal.ToString(invalidString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        public void ShouldThrowArgumentException_InToString_WhenProvidedInvalidHexadecimalString()
        {
            Func<string> act = () => Hexadecimal.ToString(_invalidHexadecimalTestString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputHexadecimalString}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InToByteArray_WhenProvidedNullEmptyOrWhiteSpaceString(string invalidString)
        {
            Func<byte[]> act = () => Hexadecimal.ToByteArray(invalidString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        public void ShouldThrowArgumentException_InToByteArray_WhenProvidedInvalidHexadecimalString()
        {
            Func<byte[]> act = () => Hexadecimal.ToByteArray(_invalidHexadecimalTestString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputHexadecimalString}*");
        }

        [TestMethod]
        [DataRow(_invalidHexadecimalTestString, false)]
        [DataRow(_uppercaseHexadecimalTestStringWithoutPrefix, true)]
        public void ShouldValiteHexadecimalString_InIsValidHexadecimalString(string hexadecimalString, bool isValidHexadecimalString)
        {
            var isValid = Hexadecimal.IsValidHexadecimalString(hexadecimalString);

            isValid.Should().Be(isValidHexadecimalString);
        }

        [TestMethod]
        [DataRow(false, CharacterCasing.Upper, _uppercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(true, CharacterCasing.Upper, _uppercaseHexadecimalTestStringWithPrefix)]
        [DataRow(false, CharacterCasing.Lower, _lowercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(true, CharacterCasing.Lower, _lowercaseHexadecimalTestStringWithPrefix)]
        [DataRow(false, CharacterCasing.Normal, _lowercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(true, CharacterCasing.Normal, _lowercaseHexadecimalTestStringWithPrefix)]
        public void ShouldEncodeToHexadecimalStringAndMatch_InToHexadecimalString(bool includeHexIndicatorPrefix, CharacterCasing outputCharacterCasing, string expectedHexadecimalString)
        {
            HexadecimalEncodingOptions hexadecimalEncodingOptions = new(includeHexIndicatorPrefix, outputCharacterCasing);
            var hexadecimalString = Hexadecimal.ToHexadecimalString(_testByteArray, hexadecimalEncodingOptions);

            hexadecimalString.Should().Be(expectedHexadecimalString);
        }

        [TestMethod]
        public void ShouldDecodeFromBase64StringAndMatch_InToString()
        {
            var decodedPlainString = Hexadecimal.ToString(_uppercaseHexadecimalTestStringWithoutPrefix);

            decodedPlainString.Should().Be(_plainTestString);
        }
    }
}