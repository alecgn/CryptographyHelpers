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
        private readonly Hexadecimal _hexadecimal = new();
        private const string _invalidHexadecimalTestString = "000102030405060708090A0B0C0D0E0FG";
        private const string _hexadecimalTestString = "000102030405060708090A0B0C0D0E0F";
        private readonly byte[] _testByteArray = new byte[]
        {
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
        };
        private const string _uppercaseHexadecimalTestString = "000102030405060708090A0B0C0D0E0F";
        private const string _uppercaseHexadecimalTestStringWithPrefix = "0x000102030405060708090A0B0C0D0E0F";
        private const string _lowercaseHexadecimalTestString = "000102030405060708090a0b0c0d0e0f";
        private const string _lowercaseHexadecimalTestStringWithPrefix = "0x000102030405060708090a0b0c0d0e0f";

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InToHexadecimalString_WhenProvidedNullEmptyOrWhiteSpaceString(string invalidString)
        {
            Func<string> act = () => _hexadecimal.ToHexadecimalString(invalidString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldThrowArgumentException_InToHexadecimalString_WhenProvidedNullOrEmptyByteArray(byte[] invalidByteArray)
        {
            Func<string> act = () => _hexadecimal.ToHexadecimalString(invalidByteArray);

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
            Func<string> act = () => _hexadecimal.ToString(invalidString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        public void ShouldThrowArgumentException_InToString_WhenProvidedInvalidHexadecimalString()
        {
            Func<string> act = () => _hexadecimal.ToString(_invalidHexadecimalTestString);

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
            Func<byte[]> act = () => _hexadecimal.ToByteArray(invalidString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        public void ShouldThrowArgumentException_InToByteArray_WhenProvidedInvalidHexadecimalString()
        {
            Func<byte[]> act = () => _hexadecimal.ToByteArray(_invalidHexadecimalTestString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputHexadecimalString}*");
        }

        [TestMethod]
        [DataRow(_invalidHexadecimalTestString, false)]
        [DataRow(_hexadecimalTestString, true)]
        public void ShouldValiteHexadecimalString_InIsValidHexadecimalString(string hexadecimalString, bool isValidHexadecimalString)
        {
            var isValid = _hexadecimal.IsValidHexadecimalString(hexadecimalString);

            isValid.Should().Be(isValidHexadecimalString);
        }

        [TestMethod]
        [DataRow(false, CharacterCasing.Upper, _uppercaseHexadecimalTestString)]
        [DataRow(true, CharacterCasing.Upper, _uppercaseHexadecimalTestStringWithPrefix)]
        [DataRow(false, CharacterCasing.Lower, _lowercaseHexadecimalTestString)]
        [DataRow(true, CharacterCasing.Lower, _lowercaseHexadecimalTestStringWithPrefix)]
        [DataRow(false, CharacterCasing.Normal, _lowercaseHexadecimalTestString)]
        [DataRow(true, CharacterCasing.Normal, _lowercaseHexadecimalTestStringWithPrefix)]
        public void ShouldMatchHexadecimalString_InToHexadecimalString(bool includeHexIndicatorPrefix, CharacterCasing outputCharacterCasing, string expectedHexadecimalString)
        {
            var hexadecimalString = _hexadecimal.ToHexadecimalString(_testByteArray, includeHexIndicatorPrefix, outputCharacterCasing);

            hexadecimalString.Should().Be(expectedHexadecimalString);
        }
    }
}