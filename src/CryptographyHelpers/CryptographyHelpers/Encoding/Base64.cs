using CryptographyHelpers.ByteArrays;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Strings;
using System;
using System.Text.RegularExpressions;

namespace CryptographyHelpers.Encoding
{
    public static class Base64
    {
        private static Regex _regexBase64String = null;
        private const int Base64ChunkSize = 4;

        public static string ToBase64String(string plainString)
        {
            if (string.IsNullOrWhiteSpace(plainString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(plainString));
            }

            var plainStringBytes = StringUtil.GetUTF8BytesFromString(plainString);

            return ToBase64String(plainStringBytes);
        }

        public static string ToBase64String(byte[] byteArray)
        {
            if (byteArray is null || byteArray.Length == 0)
            {
                throw new ArgumentException(MessageStrings.ByteArray_InvalidInputByteArray, nameof(byteArray));
            }

            return Convert.ToBase64String(byteArray);
        }

        public static string ToString(string base64String)
        {
            if (string.IsNullOrWhiteSpace(base64String))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(base64String));
            }

            if (!IsValidBase64String(base64String))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputBase64String, nameof(base64String));
            }

            var byteArray = Convert.FromBase64String(base64String);

            return ByteArrayUtil.GetStringFromUTF8Bytes(byteArray);
        }

        public static byte[] ToByteArray(string base64String)
        {
            if (string.IsNullOrWhiteSpace(base64String))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(base64String));
            }

            if (!IsValidBase64String(base64String))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputBase64String, nameof(base64String));
            }

            return Convert.FromBase64String(base64String);
        }

        public static bool IsValidBase64String(string base64String)
        {
            _regexBase64String ??= new Regex(RegexStrings.Base64String);

            return _regexBase64String.IsMatch(base64String) && base64String.Length % Base64ChunkSize == 0;
        }
    }
}
