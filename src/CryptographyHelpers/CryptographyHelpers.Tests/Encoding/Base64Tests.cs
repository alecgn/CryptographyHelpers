//using CryptographyHelpers.IoC;
//using CryptographyHelpers.Resources;
//using CryptographyHelpers.Text.Encoding;
//using FluentAssertions;
//using Microsoft.VisualStudio.TestTools.UnitTesting;
//using System;

//namespace CryptographyHelpers.Tests.Encoding
//{
//    [TestClass]
//    public class Base64Tests
//    {
//        private const string PlainTestString = "This is a test string!";
//        private const string Base64TestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ=="; // Generated on -> https://www.convertstring.com/en/EncodeDecode/Base64Encode from the above string
//        private const string InvalidBase64TestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ=";
//        private readonly byte[] _testByteArray = new byte[]
//        {
//            0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74,
//            0x65, 0x73, 0x74, 0x20, 0x73, 0x74, 0x72, 0x69, 0x6e, 0x67, 0x21,
//        };
//        private readonly IBase64 _base64;

//        public Base64Tests()
//        {
//            _base64 = InternalServiceLocator.Instance.GetService<IBase64>();
//        }

//        [TestMethod]
//        [DataRow(null)]
//        [DataRow("")]
//        [DataRow("   ")]
//        public void ShouldThrowArgumentException_InEncodeToString_WhenProvidedNullEmptyOrWhiteSpaceString(string invalidString)
//        {
//            Func<string> func = () => _base64.EncodeToString(invalidString);

//            func.Should()
//                .ThrowExactly<ArgumentException>()
//                .WithMessage($"{MessageStrings.Strings_InvalidInputText}*");
//        }

//        [TestMethod]
//        [DataRow(null)]
//        [DataRow(new byte[0])]
//        public void ShouldThrowArgumentException_InEncodeToString_WhenProvidedNullOrEmptyByteArray(byte[] invalidByteArray)
//        {
//            Func<string> func = () => _base64.EncodeToString(invalidByteArray);

//            func.Should()
//                .ThrowExactly<ArgumentException>()
//                .WithMessage($"{MessageStrings.Bytes_InvalidInputBytes}*");
//        }

//        [TestMethod]
//        [DataRow(null)]
//        [DataRow("")]
//        [DataRow("   ")]
//        public void ShouldThrowArgumentException_InDecodeToString_WhenProvidedNullEmptyOrWhiteSpaceBase64String(string nullEmptyOrWhiteSpaceBase64String)
//        {
//            Func<string> func = () => _base64.DecodeToString(nullEmptyOrWhiteSpaceBase64String);

//            func.Should()
//                .ThrowExactly<ArgumentException>()
//                .WithMessage($"{MessageStrings.Strings_InvalidInputText}*");
//        }

//        [TestMethod]
//        public void ShouldThrowArgumentException_InDecodeToString_WhenProvidedInvalidBase64String()
//        {
//            Func<string> func = () => _base64.DecodeToString(InvalidBase64TestString);

//            func.Should()
//                .ThrowExactly<ArgumentException>()
//                .WithMessage($"{MessageStrings.Strings_InvalidBase64InputString}*");
//        }

//        [TestMethod]
//        [DataRow(null)]
//        [DataRow("")]
//        [DataRow("   ")]
//        public void ShouldThrowArgumentException_InDecodeString_WhenProvidedNullEmptyOrWhiteSpaceBase64String(string nullEmptyOrWhiteSpaceBase64String)
//        {
//            Func<byte[]> func = () => _base64.DecodeString(nullEmptyOrWhiteSpaceBase64String);

//            func.Should()
//                .ThrowExactly<ArgumentException>()
//                .WithMessage($"{MessageStrings.Strings_InvalidInputText}*");
//        }

//        [TestMethod]
//        public void ShouldThrowArgumentException_InDecodeString_WhenProvidedInvalidBase64String()
//        {
//            Func<byte[]> func = () => _base64.DecodeString(InvalidBase64TestString);

//            func.Should()
//                .ThrowExactly<ArgumentException>()
//                .WithMessage($"{MessageStrings.Strings_InvalidBase64InputString}*");
//        }

//        [TestMethod]
//        public void ShouldEncodeToBase64StringAndMatch_InEncodeToString_WhenProvidedPlainString()
//        {
//            var base64EncodedString = _base64.EncodeToString(PlainTestString);

//            base64EncodedString.Should().Be(Base64TestString);
//        }

//        [TestMethod]
//        public void ShouldEncodeToBase64StringAndMatch_InEncodeToString_WhenProvidedByteArray()
//        {
//            var base64EncodedString = _base64.EncodeToString(_testByteArray);

//            base64EncodedString.Should().Be(Base64TestString);
//        }

//        [TestMethod]
//        public void ShouldDecodeFromBase64StringAndMatch_InDecodeToString()
//        {
//            var decodedPlainString = _base64.DecodeToString(Base64TestString);

//            decodedPlainString.Should().Be(PlainTestString);
//        }

//        [TestMethod]
//        public void ShouldConvertToByteArrayAndMatch_InDecodeString()
//        {
//            var byteArray = _base64.DecodeString(Base64TestString);

//            byteArray.Should().BeEquivalentTo(_testByteArray);
//        }

//        [TestMethod]
//        [DataRow(Base64TestString, true)]
//        [DataRow(InvalidBase64TestString, false)]
//        public void ShouldValiteBase64String_InIsValidBase64String(string base64String, bool isValidBase64String)
//        {
//            var isValid = _base64.IsValidEncodedString(base64String);

//            isValid.Should().Be(isValidBase64String);
//        }
//    }
//}