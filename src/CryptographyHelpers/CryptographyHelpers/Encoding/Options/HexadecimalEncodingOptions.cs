namespace CryptographyHelpers.Encoding
{
    public class HexadecimalEncodingOptions
    {
        public HexadecimalEncodingOptions()
        {
            IncludeHexIndicatorPrefix = false;
            OutputCharacterCasing = CharacterCasing.Upper;
        }

        public HexadecimalEncodingOptions(bool includeHexIndicatorPrefix, CharacterCasing outputCharacterCasing)
        {
            IncludeHexIndicatorPrefix = includeHexIndicatorPrefix;
            OutputCharacterCasing = outputCharacterCasing;
        }

        public bool IncludeHexIndicatorPrefix { get; private set; }

        public CharacterCasing OutputCharacterCasing { get; private set; }
    }
}