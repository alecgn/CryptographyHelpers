namespace CryptographyHelpers.Encoding
{
    public interface IHexadecimal
    {
        string ToHexadecimalString(string plainString, bool includeHexIndicatorPrefix = false, CharacterCasing outputHexCharacterCasing = CharacterCasing.Upper);

        string ToHexadecimalString(byte[] byteArray, bool includeHexIndicatorPrefix = false, CharacterCasing outputCharacterCasing = CharacterCasing.Upper);

        string ToString(string hexadecimalString);

        byte[] ToByteArray(string hexadecimalString);

        bool IsValidHexadecimalString(string hexadecimalString);
    }
}
