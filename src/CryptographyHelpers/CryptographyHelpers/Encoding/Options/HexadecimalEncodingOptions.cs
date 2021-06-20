using CryptographyHelpers.Text;

namespace CryptographyHelpers.Encoding
{
    public struct HexadecimalEncodingOptions
    {
        public HexadecimalEncodingOptions(bool includeHexadecimalIndicatorPrefix = false, CharacterCasing outputCharacterCasing = CharacterCasing.Upper)
        {
            IncludeHexadecimalIndicatorPrefix = includeHexadecimalIndicatorPrefix;
            OutputCharacterCasing = outputCharacterCasing;
        }

        public bool IncludeHexadecimalIndicatorPrefix { get; private set; }

        public CharacterCasing OutputCharacterCasing { get; private set; }
    }
}