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
    public class HashBaseTests
    {
        private readonly MD5 _hashBase; // "HashBase" is an abastrat class and can't be instantiated, so we will use MD5 here (could be any other class wich inherits from it)
        private const string HexadecimalTestString = "546869732069732061207465737420737472696E6721";
        private const string InvalidHexadecimalTestString = "546869732069732061207465737420737472696E672G";
        private const string Base64TestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ==";
        private const string InvalidBase64TestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ=";

        public HashBaseTests()
        {
            _hashBase = new MD5();
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldNotReturnSuccess_InComputeHash_WhenProvidedNullEmptyOrWhiteSpaceStringToComputeHash(string nullEmptyOrWhiteSpaceString)
        {
            var expectedHashResult = new GenericHashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_InputStringRequired,
            };

            var hashResult = _hashBase.ComputeHash(nullEmptyOrWhiteSpaceString);

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldNotReturnSuccess_InComputeHash_WhenProvidedNullOrEmptyByteArrayToComputeHash(byte[] nullOrEmptyByteArray)
        {
            var expectedHashResult = new GenericHashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_InputBytesRequired,
            };

            var hashResult = _hashBase.ComputeHash(nullOrEmptyByteArray);

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        [DataRow(@"Z:\8f297b5d-e0d4-4c91-bc45-38a857c20fa2\cf8152bb-d185-4127-a811-975460bca6fc.txt")]
        public void ShouldNotReturnSuccess_InComputeFileHash_WhenProvidedInvalidFilePathToComputeHash(string invalidFilePath)
        {
            var expectedHashResult = new GenericHashResult()
            {
                Success = false,
                Message = $@"{MessageStrings.File_PathNotFound} ""{invalidFilePath}"".",
            };

            var hashResult = _hashBase.ComputeFileHash(invalidFilePath);

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldNotReturnSuccess_InVerifyHash_WhenProvidedNullEmptyOrWhitespaceStringToComputeHash(string nullEmptyOrWhitespaceString)
        {
            var expectedHashResult = new GenericHashResult()
            {
                Success = false,
                Message = MessageStrings.Strings_InvalidInputString,
            };

            var hashResult = _hashBase.VerifyHash(nullEmptyOrWhitespaceString, HexadecimalTestString);

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow("")]
        [DataRow("   ")]
        public void ShouldNotReturnSuccess_InVerifyHash_WhenProvidedNullEmptyOrWhitespaceVerificationHashString(string verificationHashString)
        {
            var expectedHashResult = new GenericHashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_VerificationHashStringRequired,
            };

            var hashResult = _hashBase.VerifyHash(Guid.NewGuid().ToString(), verificationHashString);

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        public void ShouldNotReturnSuccess_InVerifyHash_WhenProvidedInvalidHexadecimalVerificationHashString()
        {
            var expectedHashResult = new GenericHashResult()
            {
                Success = false,
                Message = MessageStrings.Strings_InvalidInputHexadecimalString,
            };

            var hashResult = _hashBase.VerifyHash(Guid.NewGuid().ToString(), InvalidHexadecimalTestString, new SeekOptions(), EncodingType.Hexadecimal);

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        public void ShouldNotReturnSuccess_InVerifyHash_WhenProvidedInvalidBase64VerificationHashString()
        {
            var expectedHashResult = new GenericHashResult()
            {
                Success = false,
                Message = MessageStrings.Strings_InvalidInputBase64String,
            };

            var hashResult = _hashBase.VerifyHash(Guid.NewGuid().ToString(), InvalidBase64TestString, new SeekOptions(), EncodingType.Base64);

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DataRow(null)]
        [DataRow(new byte[0])]
        public void ShouldNotReturnSuccess_InVerifyHash_WhenProvidedNullOrEmptyHashByteArray(byte[] nullOrEmptyHashByteArray)
        {
            var expectedHashResult = new GenericHashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_VerificationHashBytesRequired,
            };

            var hashResult = _hashBase.VerifyHash(nullOrEmptyHashByteArray, Array.Empty<byte>());

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }
    }
}
