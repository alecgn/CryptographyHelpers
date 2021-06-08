using CryptographyHelpers.Encoding.Enums;
using CryptographyHelpers.Hash;
using CryptographyHelpers.Hash.Results;
using CryptographyHelpers.Options;
using CryptographyHelpers.Resources;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;

namespace CryptographyHelpers.Tests.Hash
{
    [TestClass]
    public class HashTests
    {
        private readonly IHash _hash;
        private const string InvalidHexadecimalTestString = "546869732069732061207465737420737472696E672G";
        private const string InvalidBase64TestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ=";
        private const EncodingType DefaultEncodingType = EncodingType.Hexadecimal;

        public HashTests()
        {
            _hash = new MD5(); // could be any other concrete implementation
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldNotReturnSuccess_InComputeHash_WhenProvidedNullEmptyOrWhiteSpaceStringToComputeHash(string nullEmptyOrWhiteSpaceString)
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_InputStringRequired,
            };

            var hashResult = _hash.ComputeHash(nullEmptyOrWhiteSpaceString, DefaultEncodingType, new SeekOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldNotReturnSuccess_InComputeHash_WhenProvidedNullOrEmptyByteArrayToComputeHash(byte[] nullOrEmptyByteArray)
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_InputBytesRequired,
            };

            var hashResult = _hash.ComputeHash(nullOrEmptyByteArray, DefaultEncodingType, new SeekOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        [DataRow(@"Z:\8f297b5d-e0d4-4c91-bc45-38a857c20fa2\cf8152bb-d185-4127-a811-975460bca6fc.txt")]
        public void ShouldNotReturnSuccess_InComputeFileHash_WhenProvidedInvalidFilePathToComputeHash(string invalidFilePath)
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = $@"{MessageStrings.File_PathNotFound} ""{invalidFilePath}"".",
            };

            var hashResult = _hash.ComputeFileHash(invalidFilePath, DefaultEncodingType, new LongSeekOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldNotReturnSuccess_InVerifyHash_WhenProvidedNullEmptyOrWhitespaceStringToComputeHash(string nullEmptyOrWhitespaceString)
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Strings_InvalidInputString,
            };

            var hashResult = _hash.VerifyHash(nullEmptyOrWhitespaceString, Guid.NewGuid().ToString(), DefaultEncodingType, new SeekOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldNotReturnSuccess_InVerifyHash_WhenProvidedNullEmptyOrWhitespaceVerificationHashString(string nullEmptyOrWhitespaceVerificationHashString)
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_VerificationHashStringRequired,
            };

            var hashResult = _hash.VerifyHash(Guid.NewGuid().ToString(), nullEmptyOrWhitespaceVerificationHashString, DefaultEncodingType, new SeekOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        public void ShouldNotReturnSuccess_InVerifyHash_WhenProvidedInvalidHexadecimalVerificationHashString()
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Strings_InvalidInputHexadecimalString,
            };

            var hashResult = _hash.VerifyHash(Guid.NewGuid().ToString(), InvalidHexadecimalTestString, EncodingType.Hexadecimal, new SeekOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        public void ShouldNotReturnSuccess_InVerifyHash_WhenProvidedInvalidBase64VerificationHashString()
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Strings_InvalidInputBase64String,
            };

            var hashResult = _hash.VerifyHash(Guid.NewGuid().ToString(), InvalidBase64TestString, EncodingType.Base64, new SeekOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldNotReturnSuccess_InVerifyHash_WhenProvidedNullOrEmptyVerificationHashByteArray(byte[] nullOrEmptyVerificationHashByteArray)
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_VerificationHashBytesRequired,
            };

            var hashResult = _hash.VerifyHash(Array.Empty<byte>(), nullOrEmptyVerificationHashByteArray, new SeekOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldNotReturnSuccess_InVerifyFileHash_WhenProvidedNullEmptyOrWhitespaceVerificationHashString(string nullEmptyOrWhitespaceVerificationHashString)
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_VerificationHashStringRequired,
            };

            var hashResult = _hash.VerifyFileHash(Guid.NewGuid().ToString(), nullEmptyOrWhitespaceVerificationHashString, DefaultEncodingType, new LongSeekOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        public void ShouldNotReturnSuccess_InVerifyFileHash_WhenProvidedInvalidHexadecimalVerificationHashString()
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Strings_InvalidInputHexadecimalString,
            };

            var hashResult = _hash.VerifyFileHash(Guid.NewGuid().ToString(), InvalidHexadecimalTestString, EncodingType.Hexadecimal, new LongSeekOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        public void ShouldNotReturnSuccess_InVerifyFileHash_WhenProvidedInvalidBase64VerificationHashString()
        {
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Strings_InvalidInputBase64String,
            };

            var hashResult = _hash.VerifyFileHash(Guid.NewGuid().ToString(), InvalidBase64TestString, EncodingType.Base64, new LongSeekOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
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

            var hashResult = _hash.VerifyFileHash(Guid.NewGuid().ToString(), nullOrEmptyVerificationHashByteArray, new LongSeekOptions());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }
    }
}
