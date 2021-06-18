using System;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers
{
    [ExcludeFromCodeCoverage]
    public class LongRangeOptions
    {
        public LongRangeOptions()
        {
            Start = 0L;
            End = 0L;
        }

        public LongRangeOptions(long start, long end)
        {
            if (end > start)
            {
                throw new ArgumentOutOfRangeException(nameof(end), $"{nameof(end)} parameter value cannot be greater than {nameof(start)} parameter value.");
            }

            Start = start;
            End = end;
        }

        public long Start { get; private set; }

        public long End { get; private set; }
    }
}