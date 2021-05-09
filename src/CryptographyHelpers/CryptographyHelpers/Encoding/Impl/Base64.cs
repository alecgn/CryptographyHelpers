using CryptographyHelpers.Resources;
using CryptographyHelpers.Util;
using System;
using System.Text.RegularExpressions;

namespace CryptographyHelpers.Encoding
{
    public class Base64 : IBase64
    {
        private Regex _regexBase64String = null;
        private const int _base64ChunkSize = 4;

        public string ToBase64String(string plainString)
        {
            if (string.IsNullOrWhiteSpace(plainString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(plainString));
            }

            var plainStringBytes = StringUtil.GetUTF8BytesFromString(plainString);

            return ToBase64String(plainStringBytes);
        }

        public string ToBase64String(byte[] byteArray)
        {
            if (byteArray is null || byteArray.Length == 0)
            {
                throw new ArgumentException(MessageStrings.ByteArray_InvalidInputByteArray, nameof(byteArray));
            }

            return Convert.ToBase64String(byteArray);
        }

        public string ToString(string base64String)
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

            return StringUtil.GetStringFromUTF8Bytes(byteArray);
        }

        public byte[] ToByteArray(string base64String)
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

        public bool IsValidBase64String(string base64String)
        {
            _regexBase64String ??= new Regex(RegexStrings.Base64String);

            return _regexBase64String.IsMatch(base64String) && base64String.Length % _base64ChunkSize == 0;
        }
    }
}
