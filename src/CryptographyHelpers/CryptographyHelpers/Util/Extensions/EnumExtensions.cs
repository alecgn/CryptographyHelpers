using System;

namespace CryptographyHelpers.Util.Extensions
{
    internal static class EnumExtensions
    {
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