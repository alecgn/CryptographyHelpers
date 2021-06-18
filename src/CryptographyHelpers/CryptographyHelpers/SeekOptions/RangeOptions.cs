using System;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers
{
    [ExcludeFromCodeCoverage]
    public class RangeOptions
    {
        public RangeOptions()
        {
            Start = 0;
            End = 0;
        }

        public RangeOptions(int start, int end)
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