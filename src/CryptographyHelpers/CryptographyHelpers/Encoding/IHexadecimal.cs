namespace CryptographyHelpers.Encoding
{
    public interface IHexadecimal
    {
        string ToHexadecimalString(string plainString, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions);

        string ToHexadecimalString(byte[] byteArray, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions);

        string ToString(string hexadecimalString);

        byte[] ToByteArray(string hexadecimalString);

        bool IsValidHexadecimalString(string hexadecimalString);
    }
}
