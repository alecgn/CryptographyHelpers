using CryptographyHelpers.Encoding.Options;
using CryptographyHelpers.Enums;
using CryptographyHelpers.Extensions;
using CryptographyHelpers.Resources;
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
        private const string HexadecimalPrefix = "0x";
        private const string HexadecimalFormatLower = "x2";
        private const string HexadecimalFormatUpper = "X2";
        private static Regex _regexHexadecimalString = null;

        public static string ToHexadecimalString(string plainString) =>
            ToHexadecimalString(plainString, new HexadecimalEncodingOptions());

        public static string ToHexadecimalString(string plainString, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions)
        {
            if (string.IsNullOrWhiteSpace(plainString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(plainString));
            }

            var plainStringBytes = plainString.ToUTF8Bytes();

            return ToHexadecimalString(plainStringBytes, hexadecimalOutputEncodingOptions);
        }

        public static string ToHexadecimalString(byte[] byteArray) =>
            ToHexadecimalString(byteArray, new HexadecimalEncodingOptions());

        public static string ToHexadecimalString(byte[] byteArray, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions)
        {
            if (byteArray is null || byteArray.Length == 0)
            {
                throw new ArgumentException(MessageStrings.ByteArray_InvalidInputByteArray, nameof(byteArray));
            }

            var hexadecimalString = new StringBuilder();

            if (hexadecimalOutputEncodingOptions.IncludeHexadecimalIndicatorPrefix)
            {
                hexadecimalString.Append(HexadecimalPrefix);
            }

            var hexadecimalFormat = hexadecimalOutputEncodingOptions.OutputCharacterCasing == CharacterCasing.Upper ? HexadecimalFormatUpper : HexadecimalFormatLower;

            for (var i = 0; i < byteArray.Length; i++)
            {
                hexadecimalString.Append(byteArray[i].ToString(hexadecimalFormat));
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

            if (hexadecimalString.StartsWith(HexadecimalPrefix, StringComparison.OrdinalIgnoreCase))
            {
                hexadecimalString = hexadecimalString[2..];
            }

            var byteArray = ToByteArray(hexadecimalString);

            return byteArray.ToUTF8String();
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

            if (hexadecimalString.StartsWith(HexadecimalPrefix, StringComparison.OrdinalIgnoreCase))
            {
                hexadecimalString = hexadecimalString[2..];
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
