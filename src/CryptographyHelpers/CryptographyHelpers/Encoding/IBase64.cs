namespace CryptographyHelpers.Encoding
{
    public interface IBase64
    {
        public string ToBase64String(string plainString);

        public string ToBase64String(byte[] byteArray);

        public string ToString(string base64String);

        public byte[] ToByteArray(string base64String);

        public bool IsValidBase64String(string base64String);
    }
}
