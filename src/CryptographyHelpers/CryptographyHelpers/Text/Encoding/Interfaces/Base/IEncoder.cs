namespace CryptographyHelpers.Text.Encoding
{
    public interface IEncoder
    {
        string EncodeToString(string plainString);

        string EncodeToString(byte[] byteArray);

        string DecodeToString(string encodedString);

        byte[] DecodeString(string encodedString);

        bool IsValidEncodedString(string encodedString);
    }
}