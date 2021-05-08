namespace CryptographyHelpers.Strings
{
    public static class StringUtil
    {
        public static byte[] GetUTF8BytesFromString(string @string) =>
            System.Text.Encoding.UTF8.GetBytes(@string);
    }
}