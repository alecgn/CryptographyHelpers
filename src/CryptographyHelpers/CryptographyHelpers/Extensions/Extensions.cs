using CryptographyHelpers.Encoding;
using CryptographyHelpers.IoC;
using System;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.Extensions
{
    public static class Extensions
    {
        private static ServiceLocator _serviceLocator = ServiceLocator.Instance;

        [ExcludeFromCodeCoverage]
        public static byte[] ToUTF8Bytes(this string @string) =>
            System.Text.Encoding.UTF8.GetBytes(@string);

        [ExcludeFromCodeCoverage]
        public static byte[] ToBytesFromBase64String(this string base64String) =>
            Convert.FromBase64String(base64String);

        [ExcludeFromCodeCoverage]
        public static string ToUTF8String(this byte[] bytes) =>
            System.Text.Encoding.UTF8.GetString(bytes);

        [ExcludeFromCodeCoverage]
        public static string ToBase64String(this byte[] bytes) =>
            Convert.ToBase64String(bytes);

        [ExcludeFromCodeCoverage]
        public static string ToHexadecimalString(this byte[] bytes) =>
            _serviceLocator.GetService<IHexadecimal>().EncodeToString(bytes);
    }
}