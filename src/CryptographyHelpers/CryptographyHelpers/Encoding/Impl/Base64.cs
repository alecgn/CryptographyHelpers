using CryptographyHelpers.Extensions;
using CryptographyHelpers.Resources;
using System;
using System.Text.RegularExpressions;

namespace CryptographyHelpers.Encoding
{
    public class Base64 : IBase64
    {
        private const int Base64ChunkSize = 4;
        private static Regex _regexBase64String = null;


        public string EncodeToString(string plainString)
        {
            if (string.IsNullOrWhiteSpace(plainString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(plainString));
            }

            var plainStringBytes = plainString.ToUTF8Bytes();

            return EncodeToString(plainStringBytes);
        }

        public string EncodeToString(byte[] byteArray)
        {
            if (byteArray is null || byteArray.Length == 0)
            {
                throw new ArgumentException(MessageStrings.ByteArray_InvalidInputByteArray, nameof(byteArray));
            }

            return byteArray.ToBase64String();
        }

        public string DecodeToString(string base64String)
        {
            if (string.IsNullOrWhiteSpace(base64String))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(base64String));
            }

            if (!IsValidEncodedString(base64String))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputBase64String, nameof(base64String));
            }

            var byteArray = DecodeString(base64String);

            return byteArray.ToUTF8String();
        }

        public byte[] DecodeString(string base64String)
        {
            if (string.IsNullOrWhiteSpace(base64String))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(base64String));
            }

            if (!IsValidEncodedString(base64String))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputBase64String, nameof(base64String));
            }

            return base64String.FromBase64StringToByteArray();
        }

        public bool IsValidEncodedString(string base64String)
        {
            _regexBase64String ??= new Regex(RegexStrings.Base64String);

            return _regexBase64String.IsMatch(base64String) && base64String.Length % Base64ChunkSize == 0;
        }
    }
}