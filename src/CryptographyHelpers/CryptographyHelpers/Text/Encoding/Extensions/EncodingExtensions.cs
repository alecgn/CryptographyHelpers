using CryptographyHelpers.IoC;
using System;

namespace CryptographyHelpers.Text.Encoding
{
    public static class EncodingExtensions
    {
        private static InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;


        public static byte[] ToBytesFromBase64String(this string base64String) =>
            Convert.FromBase64String(base64String);

        public static string ToBase64String(this byte[] bytes) =>
            Convert.ToBase64String(bytes);

        public static string ToHexadecimalString(this byte[] bytes) =>
            _serviceLocator.GetService<IHexadecimal>().EncodeToString(bytes);

        public static string ToUTF8String(this byte[] bytes) =>
            System.Text.Encoding.UTF8.GetString(bytes);

        public static byte[] ToUTF8Bytes(this string @string) =>
            System.Text.Encoding.UTF8.GetBytes(@string);
    }
}