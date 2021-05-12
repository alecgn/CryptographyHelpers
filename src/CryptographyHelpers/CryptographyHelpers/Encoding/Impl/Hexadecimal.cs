using CryptographyHelpers.Resources;
using CryptographyHelpers.Util;
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
        private const string HexadecimalPrefixLower = "0x";
        private const string HexadecimalPrefixUpper = "0X";
        private const string HexadecimalFormatLower = "x2";
        private const string HexadecimalFormatUpper = "X2";
        private Regex _regexHexadecimalString = null;

        public string ToHexadecimalString(string plainString, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions)
        {
            if (string.IsNullOrWhiteSpace(plainString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(plainString));
            }

            var plainStringBytes = StringUtil.GetUTF8BytesFromString(plainString);

            return ToHexadecimalString(plainStringBytes, hexadecimalOutputEncodingOptions);
        }

        public string ToHexadecimalString(byte[] byteArray, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions)
        {
            if (byteArray is null || byteArray.Length == 0)
            {
                throw new ArgumentException(MessageStrings.ByteArray_InvalidInputByteArray, nameof(byteArray));
            }

            var hexadecimalString = new StringBuilder();

            if (hexadecimalOutputEncodingOptions.IncludeHexadecimalIndicatorPrefix)
            {
                hexadecimalString.Append(HexadecimalPrefixLower);
            }

            var hexadecimalFormat = hexadecimalOutputEncodingOptions.OutputCharacterCasing == CharacterCasing.Upper ? HexadecimalFormatUpper : HexadecimalFormatLower;

            for (var i = 0; i < byteArray.Length; i++)
            {
                hexadecimalString.Append(byteArray[i].ToString(hexadecimalFormat));
            }

            return hexadecimalString.ToString();
        }

        public string ToString(string hexadecimalString)
        {
            if (string.IsNullOrWhiteSpace(hexadecimalString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(hexadecimalString));
            }

            if (!IsValidHexadecimalString(hexadecimalString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputHexadecimalString, nameof(hexadecimalString));
            }

            if (hexadecimalString.StartsWith(HexadecimalPrefixLower) || hexadecimalString.StartsWith(HexadecimalPrefixUpper))
            {
                hexadecimalString = hexadecimalString[2..];
            }

            var byteArray = ToByteArray(hexadecimalString);

            return StringUtil.GetStringFromUTF8Bytes(byteArray);
        }

        public byte[] ToByteArray(string hexadecimalString)
        {
            if (string.IsNullOrWhiteSpace(hexadecimalString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputString, nameof(hexadecimalString));
            }

            if (!IsValidHexadecimalString(hexadecimalString))
            {
                throw new ArgumentException(MessageStrings.Strings_InvalidInputHexadecimalString, nameof(hexadecimalString));
            }

            if (hexadecimalString.StartsWith(HexadecimalPrefixLower) || hexadecimalString.StartsWith(HexadecimalPrefixUpper))
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

        public bool IsValidHexadecimalString(string hexadecimalString)
        {
            _regexHexadecimalString ??= new Regex(RegexStrings.HexadecimalString);

            return _regexHexadecimalString.IsMatch(hexadecimalString) && hexadecimalString.Length % HexadecimalChunkSize == 0;
        }

        private IEnumerable<string> ChunkHexadecimalString(string hexadecimalString)
        {
            for (var i = 0; i < hexadecimalString.Length; i += HexadecimalChunkSize)
            {
                yield return hexadecimalString.Substring(i, HexadecimalChunkSize);
            }
        }
    }
}
