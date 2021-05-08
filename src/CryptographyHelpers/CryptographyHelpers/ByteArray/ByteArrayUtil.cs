namespace CryptographyHelpers.ByteArrays
{
    public static class ByteArrayUtil
    {
        public static string GetStringFromUTF8Bytes(byte[] byteArray) =>
            System.Text.Encoding.UTF8.GetString(byteArray);
    }
}
