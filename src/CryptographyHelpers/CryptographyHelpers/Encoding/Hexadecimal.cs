using CryptographyHelpers.ByteArrays;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Strings;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace CryptographyHelpers.Encoding
{
    public static class Hexadecimal
    {
        private const int HexadecimalChunkSize = 2;
        private const int HexadecimalBase = 16;
        private static Regex _regexHexadecimalString = null;

        public static string ToHexadecimalString(string plainString, bool includeHexIndicatorPrefix = false, CharacterCasing outputHexCharacterCasing = CharacterCasing.Upper)
        {
            if (string.IsNullOrWhiteSpace(plainString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(plainString));
            }

            var plainStringBytes = StringUtil.GetUTF8BytesFromString(plainString);

            return ToHexadecimalString(plainStringBytes, includeHexIndicatorPrefix, outputHexCharacterCasing);
        }

        public static string ToHexadecimalString(byte[] byteArray, bool includeHexIndicatorPrefix = false, CharacterCasing outputCharacterCasing = CharacterCasing.Upper)
        {
            if (byteArray is null || byteArray.Length == 0)
            {
                throw new ArgumentException(MessageStrings.ByteArray_InvalidInputByteArray, nameof(byteArray));
            }

            var hexadecimalString = new StringBuilder();

            if (includeHexIndicatorPrefix)
            {
                hexadecimalString.Append("0x");
            }

            var hexFormat = outputCharacterCasing == CharacterCasing.Upper ? "X2" : "x2";

            for (var i = 0; i < byteArray.Length; i++)
            {
                hexadecimalString.Append(byteArray[i].ToString(hexFormat));
            }

            return hexadecimalString.ToString();
        }

        public static string ToString(string hexadecimalString)
        {
            if (string.IsNullOrWhiteSpace(hexadecimalString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(hexadecimalString));
            }

            if (!IsValidHexadecimalString(hexadecimalString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputHexadecimalString, nameof(hexadecimalString));
            }

            var byteArray = ToByteArray(hexadecimalString);

            return ByteArrayUtil.GetStringFromUTF8Bytes(byteArray);
        }

        public static byte[] ToByteArray(string hexadecimalString)
        {
            if (string.IsNullOrWhiteSpace(hexadecimalString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(hexadecimalString));
            }

            if (!IsValidHexadecimalString(hexadecimalString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputHexadecimalString, nameof(hexadecimalString));
            }

            var byteArray = new byte[hexadecimalString.Length / HexadecimalChunkSize];
            var i = 0;

            foreach (var hexadecimalValue in ChunkHexadecimalString(hexadecimalString))
            {
                byteArray[i] = Convert.ToByte(hexadecimalValue, HexadecimalBase);
                i++;
            }

            return byteArray;
        }

        public static bool IsValidHexadecimalString(string hexadecimalString)
        {
            _regexHexadecimalString ??= new Regex(RegexStrings.HexadecimalString);

            return _regexHexadecimalString.IsMatch(hexadecimalString) && hexadecimalString.Length % HexadecimalChunkSize == 0;
        }

        private static IEnumerable<string> ChunkHexadecimalString(string hexadecimalString)
        {
            for (var i = 0; i < hexadecimalString.Length; i += HexadecimalChunkSize)
            {
                yield return hexadecimalString.Substring(i, HexadecimalChunkSize);
            }
        }
    }
}
