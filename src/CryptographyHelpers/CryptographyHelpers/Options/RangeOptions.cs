using System;

namespace CryptographyHelpers.Options
{
    public struct RangeOptions
    {
        public RangeOptions(int start = 0, int end = 0)
        {
            if (end > start)
            {
                throw new ArgumentOutOfRangeException(nameof(end), $"{nameof(end)} parameter value cannot be greater than {nameof(start)} parameter value.");
            }

            Start = start;
            End = end;
        }

        public int Start { get; private set; }

        public int End { get; private set; }
    }
}