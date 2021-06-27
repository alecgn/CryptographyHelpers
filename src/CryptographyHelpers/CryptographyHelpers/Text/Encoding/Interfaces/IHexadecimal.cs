﻿namespace CryptographyHelpers.Text.Encoding
{
    public interface IHexadecimal : IEncoder
    {
        string EncodeToString(string plainString, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions);

        string EncodeToString(byte[] byteArray, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions);
    }
}