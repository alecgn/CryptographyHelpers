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
        private const string _invalidHexadecimalString = "000102030405060708090A0B0C0D0E0FG";
        private const string _testHexadecimalString = "000102030405060708090A0B0C0D0E0F";
        private readonly byte[] _testByteArray = new byte[]
        {
            0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
        };

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
            Func<string> act = () => Hexadecimal.ToString(_invalidHexadecimalString);

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
            Func<byte[]> act = () => Hexadecimal.ToByteArray(_invalidHexadecimalString);

            act.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputHexadecimalString}*");
        }

        [TestMethod]
        [DataRow(_invalidHexadecimalString, false)]
        [DataRow(_testHexadecimalString, true)]
        public void ShouldValiteHexadecimalString_InIsValidHexadecimalString(string hexadecimalString, bool isValidHexadecimalString)
        {
            var isValid = Hexadecimal.IsValidHexadecimalString(hexadecimalString);

            isValid.Should().Be(isValidHexadecimalString);
        }

        [TestMethod]
        [DataRow(false, CharacterCasing.Upper, "000102030405060708090A0B0C0D0E0F")]
        [DataRow(true, CharacterCasing.Upper, "0x000102030405060708090A0B0C0D0E0F")]
        [DataRow(false, CharacterCasing.Lower, "000102030405060708090a0b0c0d0e0f")]
        [DataRow(true, CharacterCasing.Lower, "0x000102030405060708090a0b0c0d0e0f")]
        [DataRow(false, CharacterCasing.Normal, "000102030405060708090a0b0c0d0e0f")]
        [DataRow(true, CharacterCasing.Normal, "0x000102030405060708090a0b0c0d0e0f")]
        public void ShouldMatchHexadecimalString_InToHexadecimalString(bool includeHexIndicatorPrefix, CharacterCasing outputCharacterCasing, string expectedHexadecimalString)
        {
            var hexadecimalString = Hexadecimal.ToHexadecimalString(_testByteArray, includeHexIndicatorPrefix, outputCharacterCasing);

            hexadecimalString.Should().Be(expectedHexadecimalString);
        }
    }
}
