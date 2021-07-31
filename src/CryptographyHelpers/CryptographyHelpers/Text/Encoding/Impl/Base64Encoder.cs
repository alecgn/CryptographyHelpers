using CryptographyHelpers.Resources;
using System;
using System.Text.RegularExpressions;

namespace CryptographyHelpers.Text.Encoding
{
    public class Base64Encoder : IBase64Encoder
    {
        private const int Base64ChunkSize = 4;
        private static Regex _regexBase64String = null;


        public string EncodeToString(string plainString)
        {
            if (string.IsNullOrWhiteSpace(plainString))
            {
                throw new ArgumentException(MessageStrings.Encoding_InputTextRequired, nameof(plainString));
            }

            var plainStringBytes = plainString.ToUTF8Bytes();

            return EncodeToString(plainStringBytes);
        }

        public string EncodeToString(byte[] bytes)
        {
            if (bytes is null || bytes.Length == 0)
            {
                throw new ArgumentException(MessageStrings.Bytes_InvalidInputBytes, nameof(bytes));
            }

            return bytes.ToBase64String();
        }

        public string DecodeToString(string base64String)
        {
            if (string.IsNullOrWhiteSpace(base64String))
            {
                throw new ArgumentException(MessageStrings.Decoding_InputEncodedTextRequired, nameof(base64String));
            }

            if (!IsValidEncodedString(base64String))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidBase64InputString, nameof(base64String));
            }

            var bytes = DecodeString(base64String);

            return bytes.ToUTF8String();
        }

        public byte[] DecodeString(string base64String)
        {
            if (string.IsNullOrWhiteSpace(base64String))
            {
                throw new ArgumentException(MessageStrings.Decoding_InputEncodedTextRequired, nameof(base64String));
            }

            if (!IsValidEncodedString(base64String))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidBase64InputString, nameof(base64String));
            }

            return base64String.ToBytesFromBase64String();
        }

        public bool IsValidEncodedString(string base64String)
        {
            _regexBase64String ??= new Regex(RegexStrings.Base64String);

            return _regexBase64String.IsMatch(base64String) && base64String.Length % Base64ChunkSize == 0;
        }
    }
}