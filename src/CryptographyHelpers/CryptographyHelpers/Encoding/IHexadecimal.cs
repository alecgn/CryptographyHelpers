namespace CryptographyHelpers.Encoding
{
    public interface IHexadecimal
    {
        public string ToHexadecimalString(string plainString, bool includeHexIndicatorPrefix = false, CharacterCasing outputHexCharacterCasing = CharacterCasing.Upper);

        public string ToHexadecimalString(byte[] byteArray, bool includeHexIndicatorPrefix = false, CharacterCasing outputCharacterCasing = CharacterCasing.Upper);

        public string ToString(string hexadecimalString);

        public byte[] ToByteArray(string hexadecimalString);

        public bool IsValidHexadecimalString(string hexadecimalString);
    }
}
