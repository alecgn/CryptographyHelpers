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

        internal static TTo Cast<TFrom, TTo>(this TFrom enumFrom)
            where TFrom : struct, IComparable, IFormattable, IConvertible
            where TTo : struct, IComparable, IFormattable, IConvertible
        {
            if (!typeof(TFrom).IsEnum)
                throw new ArgumentException($"{typeof(TFrom)} is not an enum type.", nameof(TFrom));

            if (!typeof(TTo).IsEnum)
                throw new ArgumentException($"{typeof(TTo)} is not an enum type.", nameof(TTo));

            try
            {
                TTo enumTo = (TTo)Enum.Parse(typeof(TTo), enumFrom.ToString());

                return enumTo;
            }
            catch
            {
                throw new InvalidCastException($"Invalid casting from enum {typeof(TFrom)} to enum {typeof(TTo)}.");
            }
        }
    }
}