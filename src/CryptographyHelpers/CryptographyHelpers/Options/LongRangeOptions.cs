using System;

namespace CryptographyHelpers
{
    public struct LongRangeOptions
    {
        public LongRangeOptions(long start = 0L, long end = 0L)
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