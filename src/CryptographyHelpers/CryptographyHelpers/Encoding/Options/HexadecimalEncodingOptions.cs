﻿using CryptographyHelpers.Text;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.Encoding
{
    [ExcludeFromCodeCoverage]
    public class HexadecimalEncodingOptions
    {
        public HexadecimalEncodingOptions()
        {
            IncludeHexadecimalIndicatorPrefix = false;
            OutputCharacterCasing = CharacterCasing.Upper;
        }

        public HexadecimalEncodingOptions(bool includeHexadecimalIndicatorPrefix, CharacterCasing outputCharacterCasing)
        {
            IncludeHexadecimalIndicatorPrefix = includeHexadecimalIndicatorPrefix;
            OutputCharacterCasing = outputCharacterCasing;
        }

        public bool IncludeHexadecimalIndicatorPrefix { get; private set; }

        public CharacterCasing OutputCharacterCasing { get; private set; }
    }
}