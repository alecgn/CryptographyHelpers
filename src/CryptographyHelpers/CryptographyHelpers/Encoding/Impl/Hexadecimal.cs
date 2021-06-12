using CryptographyHelpers.Extensions;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text;
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace CryptographyHelpers.Encoding
{
    public class Hexadecimal : IHexadecimal
    {
        private const int HexadecimalChunkSize = 2;
        private const int HexadecimalBase = 16;
        private const string HexadecimalPrefix = "0x";
        private const string HexadecimalFormatLower = "x2";
        private const string HexadecimalFormatUpper = "X2";
        private static Regex _regexHexadecimalString = null;


        public string EncodeToString(string plainString) =>
            EncodeToString(plainString, new HexadecimalEncodingOptions());

        public string EncodeToString(string plainString, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions)
        {
            if (string.IsNullOrWhiteSpace(plainString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(plainString));
            }

            var plainStringBytes = plainString.ToUTF8Bytes();

            return EncodeToString(plainStringBytes, hexadecimalOutputEncodingOptions);
        }

        public string EncodeToString(byte[] byteArray) =>
            EncodeToString(byteArray, new HexadecimalEncodingOptions());

        public string EncodeToString(byte[] byteArray, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions)
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

        public string DecodeToString(string hexadecimalString)
        {
            if (string.IsNullOrWhiteSpace(hexadecimalString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(hexadecimalString));
            }

            if (!IsValidEncodedString(hexadecimalString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputHexadecimalString, nameof(hexadecimalString));
            }

            if (hexadecimalString.StartsWith(HexadecimalPrefix, StringComparison.OrdinalIgnoreCase))
            {
                hexadecimalString = hexadecimalString[2..];
            }

            var byteArray = DecodeString(hexadecimalString);

            return byteArray.ToUTF8String();
        }

        public byte[] DecodeString(string hexadecimalString)
        {
            if (string.IsNullOrWhiteSpace(hexadecimalString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(hexadecimalString));
            }

            if (!IsValidEncodedString(hexadecimalString))
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

        public bool IsValidEncodedString(string hexadecimalString)
        {
            _regexHexadecimalString ??= new Regex(RegexStrings.HexadecimalString);

            return _regexHexadecimalString.IsMatch(hexadecimalString) && hexadecimalString.Length % HexadecimalChunkSize == 0;
        }

        internal static IEnumerable<string> ChunkHexadecimalString(string hexadecimalString)
        {
            for (var i = 0; i < hexadecimalString.Length; i += HexadecimalChunkSize)
            {
                yield return hexadecimalString.Substring(i, HexadecimalChunkSize);
            }
        }
    }
}
