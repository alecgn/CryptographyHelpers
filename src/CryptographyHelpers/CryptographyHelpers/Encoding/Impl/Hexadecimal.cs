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
        private const int _hexadecimalChunkSize = 2;
        private const int _hexadecimalBase = 16;
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

            if (hexadecimalOutputEncodingOptions.IncludeHexIndicatorPrefix)
            {
                hexadecimalString.Append("0x");
            }

            var hexFormat = hexadecimalOutputEncodingOptions.OutputCharacterCasing == CharacterCasing.Upper ? "X2" : "x2";

            for (var i = 0; i < byteArray.Length; i++)
            {
                hexadecimalString.Append(byteArray[i].ToString(hexFormat));
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

            var byteArray = new byte[hexadecimalString.Length / _hexadecimalChunkSize];
            var i = 0;

            foreach (var hexadecimalValue in ChunkHexadecimalString(hexadecimalString))
            {
                byteArray[i] = Convert.ToByte(hexadecimalValue, _hexadecimalBase);
                i++;
            }

            return byteArray;
        }

        public bool IsValidHexadecimalString(string hexadecimalString)
        {
            _regexHexadecimalString ??= new Regex(RegexStrings.HexadecimalString);

            return _regexHexadecimalString.IsMatch(hexadecimalString) && hexadecimalString.Length % _hexadecimalChunkSize == 0;
        }

        private IEnumerable<string> ChunkHexadecimalString(string hexadecimalString)
        {
            for (var i = 0; i < hexadecimalString.Length; i += _hexadecimalChunkSize)
            {
                yield return hexadecimalString.Substring(i, _hexadecimalChunkSize);
            }
        }
    }
}
