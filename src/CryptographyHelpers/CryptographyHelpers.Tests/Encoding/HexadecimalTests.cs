using CryptographyHelpers.Encoding;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace CryptographyHelpers.Tests.Encoding
{
    [TestClass]
    public class HexadecimalTests
    {
        private const string PlainTestString = "This is a test string!";
        private const string UppercaseHexadecimalTestStringWithoutPrefix = "546869732069732061207465737420737472696E6721"; // Generated on -> https://www.convertstring.com/en/EncodeDecode/HexEncode from the above string
        private const string UppercaseHexadecimalTestStringWithPrefix = "0x546869732069732061207465737420737472696E6721";
        private const string LowercaseHexadecimalTestStringWithoutPrefix = "546869732069732061207465737420737472696e6721";
        private const string LowercaseHexadecimalTestStringWithPrefix = "0x546869732069732061207465737420737472696e6721";
        private const string InvalidHexadecimalTestString = "546869732069732061207465737420737472696E672G";
        private readonly byte[] _testByteArray = new byte[]
        {
            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74,
            0x65, 0x73, 0x74, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6E, 0x67, 0x21,
        };
        private readonly IHexadecimal _hexadecimal;

        public HexadecimalTests()
        {
            _hexadecimal = InternalServiceLocator.Instance.GetService<IHexadecimal>();
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InEncodeToString_WhenProvidedNullEmptyOrWhiteSpaceString(string invalidString)
        {
            Func<string> func = () => _hexadecimal.EncodeToString(invalidString);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldThrowArgumentException_InEncodeToString_WhenProvidedNullOrEmptyByteArray(byte[] invalidByteArray)
        {
            Func<string> func = () => _hexadecimal.EncodeToString(invalidByteArray);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.ByteArray_InvalidInputByteArray}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InDecodeToString_WhenProvidedNullEmptyOrWhiteSpaceHexadecimalString(string nullEmptyOrWhiteSpaceHexadecimalString)
        {
            Func<string> func = () => _hexadecimal.DecodeToString(nullEmptyOrWhiteSpaceHexadecimalString);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        public void ShouldThrowArgumentException_InDecodeToString_WhenProvidedInvalidHexadecimalString()
        {
            Func<string> func = () => _hexadecimal.DecodeToString(InvalidHexadecimalTestString);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputHexadecimalString}*");
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldThrowArgumentException_InDecodeString_WhenProvidedNullEmptyOrWhiteSpaceHexadecimalString(string nullEmptyOrWhiteSpaceHexadecimalString)
        {
            Func<byte[]> func = () => _hexadecimal.DecodeString(nullEmptyOrWhiteSpaceHexadecimalString);

            func.Should()
                .ThrowExactly<ArgumentException>()
                .WithMessage($"{MessageStrings.Strings_InvalidInputString}*");
        }

        [TestMethod]
        public void ShouldThrowArgumentException_InDecodeString_WhenProvidedInvalidHexadecimalString()
        {
            Func<byte[]> func = () => _hexadecimal.DecodeString(InvalidHexadecimalTestString);

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
        public void ShouldEncodeToHexadecimalStringAndMatch_InEncodeToString_WhenProvidedPlainString(bool includeHexIndicatorPrefix, CharacterCasing outputCharacterCasing, string expectedHexadecimalString)
        {
            HexadecimalEncodingOptions hexadecimalEncodingOptions = new(includeHexIndicatorPrefix, outputCharacterCasing);
            var hexadecimalEncodedString = _hexadecimal.EncodeToString(PlainTestString, hexadecimalEncodingOptions);

            hexadecimalEncodedString.Should().Be(expectedHexadecimalString);
        }

        [TestMethod]
        [DataRow(false, CharacterCasing.Upper, UppercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(true, CharacterCasing.Upper, UppercaseHexadecimalTestStringWithPrefix)]
        [DataRow(false, CharacterCasing.Lower, LowercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(true, CharacterCasing.Lower, LowercaseHexadecimalTestStringWithPrefix)]
        [DataRow(false, CharacterCasing.Normal, LowercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(true, CharacterCasing.Normal, LowercaseHexadecimalTestStringWithPrefix)]
        public void ShouldEncodeToHexadecimalStringAndMatch_InEncodeToString_WhenProvidedByteArray(bool includeHexIndicatorPrefix, CharacterCasing outputCharacterCasing, string expectedHexadecimalString)
        {
            HexadecimalEncodingOptions hexadecimalEncodingOptions = new(includeHexIndicatorPrefix, outputCharacterCasing);
            var hexadecimalEncodedString = _hexadecimal.EncodeToString(_testByteArray, hexadecimalEncodingOptions);

            hexadecimalEncodedString.Should().Be(expectedHexadecimalString);
        }

        [TestMethod]
        [DataRow(UppercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(UppercaseHexadecimalTestStringWithPrefix)]
        [DataRow(LowercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(LowercaseHexadecimalTestStringWithPrefix)]
        public void ShouldDecodeFromHexadecimalStringAndMatch_InDecodeToString(string hexadecimalString)
        {
            var decodedPlainString = _hexadecimal.DecodeToString(hexadecimalString);

            decodedPlainString.Should().Be(PlainTestString);
        }

        [TestMethod]
        [DataRow(UppercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(UppercaseHexadecimalTestStringWithPrefix)]
        [DataRow(LowercaseHexadecimalTestStringWithoutPrefix)]
        [DataRow(LowercaseHexadecimalTestStringWithPrefix)]
        public void ShouldConvertToByteArrayAndMatch_InDecodeString(string hexadecimalString)
        {
            var byteArray = _hexadecimal.DecodeString(hexadecimalString);

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
            var isValid = _hexadecimal.IsValidEncodedString(hexadecimalString);

            isValid.Should().Be(isValidHexadecimalString);
        }

        [TestMethod]
        public void ShouldChunkHexadecimalString_InChunkHexadecimalString()
        {
            string[] expectedChunkedHexadecimalString = {
                "54", "68", "69", "73", "20", "69", "73", "20", "61", "20", "74",
                "65", "73", "74", "20", "73", "74", "72", "69", "6E", "67", "21"
            };

            var chunkedHexadecimalString = Hexadecimal.ChunkHexadecimalString(UppercaseHexadecimalTestStringWithoutPrefix);

            chunkedHexadecimalString.Should().BeEquivalentTo(expectedChunkedHexadecimalString);
        }
    }
}