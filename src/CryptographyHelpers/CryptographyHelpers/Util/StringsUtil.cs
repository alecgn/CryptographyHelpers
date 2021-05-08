namespace CryptographyHelpers.Util
{
    public class StringsUtil
    {
        public static byte[] GetUTF8Bytes(string @string) =>
            System.Text.Encoding.UTF8.GetBytes(@string);
    }
}