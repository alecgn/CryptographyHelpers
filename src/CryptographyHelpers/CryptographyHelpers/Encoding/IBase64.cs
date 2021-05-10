namespace CryptographyHelpers.Encoding
{
    public interface IBase64
    {
        string ToBase64String(string plainString);

        string ToBase64String(byte[] byteArray);

        string ToString(string base64String);

        byte[] ToByteArray(string base64String);

        bool IsValidBase64String(string base64String);
    }
}
