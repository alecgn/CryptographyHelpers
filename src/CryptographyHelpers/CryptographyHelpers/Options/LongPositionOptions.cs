namespace CryptographyHelpers
{
    public class LongPositionOptions
    {
        public LongPositionOptions()
        {
            Offset = 0L;
            Count = 0L;
        }

        public LongPositionOptions(long offset, long count)
        {
            Offset = offset;
            Count = count;
        }

        public long Offset { get; private set; }

        public long Count { get; private set; }
    }
}