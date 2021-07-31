namespace CryptographyHelpers.Text.Encoding
{
    public interface IHexadecimalEncoder : IEncoder
    {
        string EncodeToString(string plainString, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions);

        string EncodeToString(byte[] byteArray, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions);
    }
}