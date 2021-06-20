namespace CryptographyHelpers.Text
{
    public static class TextExtensions
    {
        public static string ToUTF8String(this byte[] bytes) =>
            System.Text.Encoding.UTF8.GetString(bytes);

        public static byte[] ToUTF8Bytes(this string @string) =>
            System.Text.Encoding.UTF8.GetBytes(@string);
    }
}