using CryptographyHelpers.Hash;
using CryptographyHelpers.Options;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Security.Authentication;

namespace CryptographyHelpers.Tests.Hash
{
    [TestClass]
    public class HashTests
    {
        private readonly HashCore _hash;
        private const string InvalidHexadecimalTestString = "546869732069732061207465737420737472696E672G";
        private const string InvalidBase64TestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ=";
        private const EncodingType DefaultEncodingType = EncodingType.Hexadecimal;

        public HashTests()
        {
            _hash = new HashCore(HashAlgorithmType.Md5); // could be any other concrete implementation
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldReturnSuccessFalse_InComputeHash_WhenProvidedNullEmptyOrWhiteSpaceStringToComputeHash(string nullEmptyOrWhiteSpaceString)
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_InputStringRequired,
            };

            var hashResult = _hash.ComputeHash(nullEmptyOrWhiteSpaceString, DefaultEncodingType, new OffsetOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldReturnSuccessFalse_InComputeHash_WhenProvidedNullOrEmptyByteArrayToComputeHash(byte[] nullOrEmptyByteArray)
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_InputBytesRequired,
            };

            var hashResult = _hash.ComputeHash(nullOrEmptyByteArray, DefaultEncodingType, new OffsetOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        [DataRow(@"Z:\8f297b5d-e0d4-4c91-bc45-38a857c20fa2\cf8152bb-d185-4127-a811-975460bca6fc.txt")]
        public void ShouldReturnSuccessFalse_InComputeFileHash_WhenProvidedInvalidFilePathToComputeHash(string invalidFilePath)
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = $@"{MessageStrings.File_PathNotFound} ""{invalidFilePath}"".",
            };

            var hashResult = _hash.ComputeFileHash(invalidFilePath, DefaultEncodingType, new LongOffsetOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldReturnSuccessFalse_InVerifyHash_WhenProvidedNullEmptyOrWhitespaceStringToComputeHash(string nullEmptyOrWhitespaceString)
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Strings_InvalidInputString,
            };

            var hashResult = _hash.VerifyHash(nullEmptyOrWhitespaceString, Guid.NewGuid().ToString(), DefaultEncodingType, new OffsetOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldReturnSuccessFalse_InVerifyHash_WhenProvidedNullEmptyOrWhitespaceVerificationHashString(string nullEmptyOrWhitespaceVerificationHashString)
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_VerificationHashStringRequired,
            };

            var hashResult = _hash.VerifyHash(Guid.NewGuid().ToString(), nullEmptyOrWhitespaceVerificationHashString, DefaultEncodingType, new OffsetOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        public void ShouldReturnSuccessFalse_InVerifyHash_WhenProvidedInvalidHexadecimalVerificationHashString()
        {
            var hashResult = _hash.VerifyHash(Guid.NewGuid().ToString(), InvalidHexadecimalTestString, EncodingType.Hexadecimal, new OffsetOptions());

            hashResult.Success.Should().BeFalse();
            hashResult.Message.Should().Contain(MessageStrings.Strings_InvalidHexadecimalInputString);
        }

        [TestMethod]
        public void ShouldReturnSuccessFalse_InVerifyHash_WhenProvidedInvalidBase64VerificationHashString()
        {
            var hashResult = _hash.VerifyHash(Guid.NewGuid().ToString(), InvalidBase64TestString, EncodingType.Base64, new OffsetOptions());

            hashResult.Success.Should().BeFalse();
            hashResult.Message.Should().Contain(MessageStrings.Strings_InvalidBase64InputString);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldReturnSuccessFalse_InVerifyHash_WhenProvidedNullOrEmptyVerificationHashByteArray(byte[] nullOrEmptyVerificationHashByteArray)
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_VerificationHashBytesRequired,
            };

            var hashResult = _hash.VerifyHash(Array.Empty<byte>(), nullOrEmptyVerificationHashByteArray, new OffsetOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldReturnSuccessFalse_InVerifyFileHash_WhenProvidedNullEmptyOrWhitespaceVerificationHashString(string nullEmptyOrWhitespaceVerificationHashString)
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_VerificationHashStringRequired,
            };

            var hashResult = _hash.VerifyFileHash(Guid.NewGuid().ToString(), nullEmptyOrWhitespaceVerificationHashString, DefaultEncodingType, new LongOffsetOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        public void ShouldReturnSuccessFalse_InVerifyFileHash_WhenProvidedInvalidHexadecimalVerificationHashString()
        {
            var hashResult = _hash.VerifyFileHash(Guid.NewGuid().ToString(), InvalidHexadecimalTestString, EncodingType.Hexadecimal, new LongOffsetOptions());

            hashResult.Success.Should().BeFalse();
            hashResult.Message.Should().Contain(MessageStrings.Strings_InvalidHexadecimalInputString);
        }

        [TestMethod]
        public void ShouldReturnSuccessFalse_InVerifyFileHash_WhenProvidedInvalidBase64VerificationHashString()
        {
            var hashResult = _hash.VerifyFileHash(Guid.NewGuid().ToString(), InvalidBase64TestString, EncodingType.Base64, new LongOffsetOptions());

            hashResult.Success.Should().BeFalse();
            hashResult.Message.Should().Contain(MessageStrings.Strings_InvalidBase64InputString);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldNotReturnSuccess_InVerifyFileHash_WhenProvidedNullOrEmptyVerificationHashByteArray(byte[] nullOrEmptyVerificationHashByteArray)
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_VerificationHashBytesRequired,
            };

            var hashResult = _hash.VerifyFileHash(Guid.NewGuid().ToString(), nullOrEmptyVerificationHashByteArray, new LongOffsetOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }
    }
}
