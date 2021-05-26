using CryptographyHelpers.Encoding;
using CryptographyHelpers.Encoding.Options;
using CryptographyHelpers.Enums;
using CryptographyHelpers.Resources;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace CryptographyHelpers.Tests.Encoding
{
    [TestClass]
    public class HexadecimalTests
    {
        private const string PlainTestString = "This is a test string!";
        private const string UppercaseHexadecimalTestStringWithoutPrefix = "546869732069732061207465737420737472696E6721";
        private const string UppercaseHexadecimalTestStringWithPrefix = "0x546869732069732061207465737420737472696E6721";
        private const string LowercaseHexadecimalTestStringWithoutPrefix = "546869732069732061207465737420737472696e6721";
        private const string LowercaseHexadecimalTestStringWithPrefix = "0x546869732069732061207465737420737472696e6721";
        private const string InvalidHexadecimalTestString = "546869732069732061207465737420737472696E672G";
        private readonly byte[] _testByteArray = new byte[]
        {
            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74,
            0x65, 0x73, 0x74, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x21,
        };

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InToHexadecimalString_WhenProvidedNullEmptyOrWhiteSpaceString(string invalidString)
        {
            Func<string> func = () => Hexadecimal.ToHexadecimalString(invalidString);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldThrowArgumentException_InToHexadecimalString_WhenProvidedNullOrEmptyByteArray(byte[] invalidByteArray)
        {
            Func<string> func = () => Hexadecimal.ToHexadecimalString(invalidByteArray);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.ByteArray_InvalidInputByteArray}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InToString_WhenProvidedNullEmptyOrWhiteSpaceHexadecimalString(string nullEmptyOrWhiteSpaceHexadecimalString)
        {
            Func<string> func = () => Hexadecimal.ToString(nullEmptyOrWhiteSpaceHexadecimalString);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        public void ShouldThrowArgumentException_InToString_WhenProvidedInvalidHexadecimalString()
        {
            Func<string> func = () => Hexadecimal.ToString(InvalidHexadecimalTestString);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputHexadecimalString}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InToByteArray_WhenProvidedNullEmptyOrWhiteSpaceHexadecimalString(string nullEmptyOrWhiteSpaceHexadecimalString)
        {
            Func<byte[]> func = () => Hexadecimal.ToByteArray(nullEmptyOrWhiteSpaceHexadecimalString);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        public void ShouldThrowArgumentException_InToByteArray_WhenProvidedInvalidHexadecimalString()
        {
            Func<byte[]> func = () => Hexadecimal.ToByteArray(InvalidHexadecimalTestString);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputHexadecimalString}*");
        }

        [TestMethod]
        [DataRow(false, CharacterCasing.Upper, UppercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(true, CharacterCasing.Upper, UppercaseHexadecimalTestStringWithPrefix)]
        [DataRow(false, CharacterCasing.Lower, LowercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(true, CharacterCasing.Lower, LowercaseHexadecimalTestStringWithPrefix)]
        [DataRow(false, CharacterCasing.Normal, LowercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(true, CharacterCasing.Normal, LowercaseHexadecimalTestStringWithPrefix)]
        public void ShouldEncodeToHexadecimalStringAndMatch_InToHexadecimalString_WhenProvidedPlainString(bool includeHexIndicatorPrefix, CharacterCasing outputCharacterCasing, string expectedHexadecimalString)
        {
            HexadecimalEncodingOptions hexadecimalEncodingOptions = new(includeHexIndicatorPrefix, outputCharacterCasing);
            var hexadecimalEncodedString = Hexadecimal.ToHexadecimalString(PlainTestString, hexadecimalEncodingOptions);

            hexadecimalEncodedString.Should().Be(expectedHexadecimalString);
        }

        [TestMethod]
        [DataRow(false, CharacterCasing.Upper, UppercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(true, CharacterCasing.Upper, UppercaseHexadecimalTestStringWithPrefix)]
        [DataRow(false, CharacterCasing.Lower, LowercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(true, CharacterCasing.Lower, LowercaseHexadecimalTestStringWithPrefix)]
        [DataRow(false, CharacterCasing.Normal, LowercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(true, CharacterCasing.Normal, LowercaseHexadecimalTestStringWithPrefix)]
        public void ShouldEncodeToHexadecimalStringAndMatch_InToHexadecimalString_WhenProvidedByteArray(bool includeHexIndicatorPrefix, CharacterCasing outputCharacterCasing, string expectedHexadecimalString)
        {
            HexadecimalEncodingOptions hexadecimalEncodingOptions = new(includeHexIndicatorPrefix, outputCharacterCasing);
            var hexadecimalEncodedString = Hexadecimal.ToHexadecimalString(_testByteArray, hexadecimalEncodingOptions);

            hexadecimalEncodedString.Should().Be(expectedHexadecimalString);
        }

        [TestMethod]
        [DataRow(UppercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(UppercaseHexadecimalTestStringWithPrefix)]
        [DataRow(LowercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(LowercaseHexadecimalTestStringWithPrefix)]
        public void ShouldDecodeFromHexadecimalStringAndMatch_InToString(string hexadecimalString)
        {
            var decodedPlainString = Hexadecimal.ToString(hexadecimalString);

            decodedPlainString.Should().Be(PlainTestString);
        }

        [TestMethod]
        [DataRow(UppercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(UppercaseHexadecimalTestStringWithPrefix)]
        [DataRow(LowercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(LowercaseHexadecimalTestStringWithPrefix)]
        public void ShouldConvertToByteArrayAndMatch_InToByteArray(string hexadecimalString)
        {
            var byteArray = Hexadecimal.ToByteArray(hexadecimalString);

            byteArray.Should().BeEquivalentTo(_testByteArray);
        }

        [TestMethod]
        [DataRow(InvalidHexadecimalTestString, false)]
        [DataRow(UppercaseHexadecimalTestStringWithoutPrefix, true)]
        [DataRow(UppercaseHexadecimalTestStringWithPrefix, true)]
        [DataRow(LowercaseHexadecimalTestStringWithoutPrefix, true)]
        [DataRow(LowercaseHexadecimalTestStringWithPrefix, true)]
        public void ShouldValiteHexadecimalString_InIsValidHexadecimalString(string hexadecimalString, bool isValidHexadecimalString)
        {
            var isValid = Hexadecimal.IsValidHexadecimalString(hexadecimalString);

            isValid.Should().Be(isValidHexadecimalString);
        }
    }
}