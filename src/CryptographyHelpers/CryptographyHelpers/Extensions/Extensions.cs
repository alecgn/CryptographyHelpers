using System;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.Extensions
{
    internal static class Extensions
    {
        [ExcludeFromCodeCoverage]
        internal static byte[] ToUTF8Bytes(this string @string) =>
            System.Text.Encoding.UTF8.GetBytes(@string);

        [ExcludeFromCodeCoverage]
        internal static string ToUTF8String(this byte[] byteArray) =>
            System.Text.Encoding.UTF8.GetString(byteArray);

        [ExcludeFromCodeCoverage]
        internal static byte[] FromBase64StringToByteArray(this string base64String) =>
            Convert.FromBase64String(base64String);

        [ExcludeFromCodeCoverage]
        internal static string ToBase64String(this byte[] byteArray) =>
            Convert.ToBase64String(byteArray);

        internal static TDest Cast<TSource, TDest>(this TSource enumSource)
            where TSource : struct, IComparable, IFormattable, IConvertible
            where TDest : struct, IComparable, IFormattable, IConvertible
        {
            if (!typeof(TSource).IsEnum)
                throw new ArgumentException($"{typeof(TSource)} is not an enum type.", nameof(TSource));

            if (!typeof(TDest).IsEnum)
                throw new ArgumentException($"{typeof(TSource)} is not an enum type.", nameof(TDest));

            TDest enumDest = (TDest)Enum.Parse(typeof(TDest), enumSource.ToString());

            return enumDest;
        }
    }
}