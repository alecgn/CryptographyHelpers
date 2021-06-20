using CryptographyHelpers.IoC;
using System;

namespace CryptographyHelpers.Encoding
{
    public static class EncodingExtensions
    {
        private static ServiceLocator _serviceLocator = ServiceLocator.Instance;


        public static byte[] ToBytesFromBase64String(this string base64String) =>
            Convert.FromBase64String(base64String);

        public static string ToBase64String(this byte[] bytes) =>
            Convert.ToBase64String(bytes);

        public static string ToHexadecimalString(this byte[] bytes) =>
            _serviceLocator.GetService<IHexadecimal>().EncodeToString(bytes);
    }
}