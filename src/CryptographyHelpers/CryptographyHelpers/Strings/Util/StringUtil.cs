namespace CryptographyHelpers.Strings
{
    public static class StringUtil
    {
        public static byte[] GetUTF8BytesFromString(string @string) =>
            System.Text.Encoding.UTF8.GetBytes(@string);

        public static string GetStringFromUTF8Bytes(byte[] byteArray) =>
            System.Text.Encoding.UTF8.GetString(byteArray);
    }
}