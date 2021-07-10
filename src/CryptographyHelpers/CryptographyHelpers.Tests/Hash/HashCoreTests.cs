using CryptographyHelpers.Hash;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;

namespace CryptographyHelpers.Tests.Hash
{
    [TestClass]
    public class HashTests
    {
        private const string PlainTestString = "This is a test string!";
        private const string InvalidHexadecimalTestString = "546869732069732061207465737420737472696E672G";
        private const string InvalidBase64TestString = "VGhpcyBpcyBhIHRlc3Qgc3RyaW5nIQ=";
        private static readonly IBase64 _base64Encoder = InternalServiceLocator.Instance.GetService<IBase64>();
        private static readonly IHexadecimal _hexadecimalEncoder = InternalServiceLocator.Instance.GetService<IHexadecimal>();

        
        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InComputeHash_WhenProvidedInvalidInputData(HashCore hashAlgorithm, byte[] invalidInputData)
        {
            HashResult hashResult;
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_InputBytesRequired,
            };

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.ComputeHash(invalidInputData);
            }

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidInputText), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InComputeHash_WhenProvidedInvalidInputText(HashCore hashAlgorithm, string invalidInputText)
        {
            HashResult hashResult;
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_InputTextRequired,
            };

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.ComputeHash(invalidInputText);
            }

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidInputFilePath), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InComputeFileHash_WhenProvidedInvalidFilePathToComputeHash(HashCore hashAlgorithm, string invalidInputFilePath)
        {
            HashResult hashResult;
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = $@"{MessageStrings.File_PathNotFound} ""{invalidInputFilePath}"".",
            };

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.ComputeFileHash(invalidInputFilePath);
            }

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyHash_WhenProvidedInvalidInputVerificationHash(HashCore hashAlgorithm, byte[] invalidInputVerificationHash)
        {
            HashResult hashResult;
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_VerificationHashBytesRequired,
            };

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.VerifyHash(Array.Empty<byte>(), invalidInputVerificationHash);
            }

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidInputText), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyHash_WhenProvidedInvalidInputText(HashCore hashAlgorithm, string invalidInputText)
        {
            HashResult hashResult;
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_InputTextRequired,
            };

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.VerifyHash(invalidInputText, Guid.NewGuid().ToString());
            }

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidEncodedInputVerificationHashString), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyHash_WhenProvidedInvalidEncodedInputVerificationHashString(HashCore hashAlgorithm, string invalidEncodedInputVerificationHashString)
        {
            HashResult hashResult;

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.VerifyHash(Guid.NewGuid().ToString(), invalidEncodedInputVerificationHashString);
            }

            hashResult.Success.Should().BeFalse();
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidInputData), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyFileHash_WhenProvidedInvalidInputVerificationHash(HashCore hashAlgorithm, byte[] invalidInputVerificationHash)
        {
            HashResult hashResult;
            var expectedHashResult = new HashResult()
            {
                Success = false,
                Message = MessageStrings.Hash_VerificationHashBytesRequired,
            };

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.VerifyFileHash(Guid.NewGuid().ToString(), invalidInputVerificationHash);
            }

            hashResult.Should().BeEquivalentTo(expectedHashResult);
        }

        [TestMethod]
        [DynamicData(nameof(GetHashAlgorithmAndInvalidEncodedInputVerificationHashString), DynamicDataSourceType.Method)]
        public void ShouldReturnSuccessFalse_InVerifyFileHash_WhenProvidedInvalidEncodedInputVerificationHashString(HashCore hashAlgorithm, string invalidEncodedInputVerificationHashString)
        {
            HashResult hashResult;

            using (hashAlgorithm)
            {
                hashResult = hashAlgorithm.VerifyFileHash(Guid.NewGuid().ToString(), invalidEncodedInputVerificationHashString);
            }

            hashResult.Success.Should().BeFalse();
        }


        private static IEnumerable<object[]> GetHashAlgorithmAndInvalidInputData() =>
            new List<object[]>()
            {
                new object[]{ new MD5(), null },
                new object[]{ new MD5(), Array.Empty<byte>() },

                new object[]{ new SHA1(), null },
                new object[]{ new SHA1(), Array.Empty<byte>() },

                new object[]{ new SHA256(), null },
                new object[]{ new SHA256(), Array.Empty<byte>() },

                new object[]{ new SHA384(), null },
                new object[]{ new SHA384(), Array.Empty<byte>() },

                new object[]{ new SHA512(), null },
                new object[]{ new SHA512(), Array.Empty<byte>() },
            };

        private static IEnumerable<object[]> GetHashAlgorithmAndInvalidInputText() =>
            new List<object[]>()
            {
                new object[]{ new MD5(), null },
                new object[]{ new MD5(), "" },
                new object[]{ new MD5(), "   " },

                new object[]{ new SHA1(), null },
                new object[]{ new SHA1(), "" },
                new object[]{ new SHA1(), "   " },

                new object[]{ new SHA256(), null },
                new object[]{ new SHA256(), "" },
                new object[]{ new SHA256(), "   " },

                new object[]{ new SHA384(), null },
                new object[]{ new SHA384(), "" },
                new object[]{ new SHA384(), "   " },

                new object[]{ new SHA512(), null },
                new object[]{ new SHA512(), "" },
                new object[]{ new SHA512(), "   " },
            };

        private static IEnumerable<object[]> GetHashAlgorithmAndInvalidInputFilePath()
        {
            var invalidFilePath = $@"Z:\{Guid.NewGuid()}\{Guid.NewGuid()}.txt";

            return new List<object[]>()
            {
                new object[]{ new MD5(), null },
                new object[]{ new MD5(), "" },
                new object[]{ new MD5(), "   " },
                new object[]{ new MD5(), invalidFilePath },

                new object[]{ new SHA1(), null },
                new object[]{ new SHA1(), "" },
                new object[]{ new SHA1(), "   " },
                new object[]{ new SHA1(), invalidFilePath },

                new object[]{ new SHA256(), null },
                new object[]{ new SHA256(), "" },
                new object[]{ new SHA256(), "   " },
                new object[]{ new SHA256(), invalidFilePath },

                new object[]{ new SHA384(), null },
                new object[]{ new SHA384(), "" },
                new object[]{ new SHA384(), "   " },
                new object[]{ new SHA384(), invalidFilePath },

                new object[]{ new SHA512(), null },
                new object[]{ new SHA512(), "" },
                new object[]{ new SHA512(), "   " },
                new object[]{ new SHA512(), invalidFilePath },
            };
        }

        private static IEnumerable<object> GetHashAlgorithmAndInvalidEncodedInputVerificationHashString()
        {
            var randomBytes = CryptographyUtils.GenerateRandomBytes(10);
            var invalidHexadecimalEncodedString = _hexadecimalEncoder.EncodeToString(randomBytes).Substring(1);
            var invalidBase64EncodedString = _base64Encoder.EncodeToString(randomBytes).Substring(1);

            return new List<object[]>()
            {
                new object[]{ new MD5(), null },
                new object[]{ new MD5(), "" },
                new object[]{ new MD5(), "   " },
                new object[]{ new MD5(), invalidHexadecimalEncodedString },
                new object[]{ new MD5(), invalidBase64EncodedString },

                new object[]{ new SHA1(), null },
                new object[]{ new SHA1(), "" },
                new object[]{ new SHA1(), "   " },
                new object[]{ new SHA1(), invalidHexadecimalEncodedString },
                new object[]{ new SHA1(), invalidBase64EncodedString },

                new object[]{ new SHA256(), null },
                new object[]{ new SHA256(), "" },
                new object[]{ new SHA256(), "   " },
                new object[]{ new SHA256(), invalidHexadecimalEncodedString },
                new object[]{ new SHA256(), invalidBase64EncodedString },

                new object[]{ new SHA384(), null },
                new object[]{ new SHA384(), "" },
                new object[]{ new SHA384(), "   " },
                new object[]{ new SHA384(), invalidHexadecimalEncodedString },
                new object[]{ new SHA384(), invalidBase64EncodedString },

                new object[]{ new SHA512(), null },
                new object[]{ new SHA512(), "" },
                new object[]{ new SHA512(), "   " },
                new object[]{ new SHA512(), invalidHexadecimalEncodedString },
                new object[]{ new SHA512(), invalidBase64EncodedString },
            };
        }
    }
}