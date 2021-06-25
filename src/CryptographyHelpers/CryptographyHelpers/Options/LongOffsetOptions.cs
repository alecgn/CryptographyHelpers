namespace CryptographyHelpers.Options
{
    public struct LongOffsetOptions
    {
        public LongOffsetOptions(long offset = 0L, long count = 0L)
        {
            Offset = offset;
            Count = count;
        }

        public long Offset { get; private set; }

        public long Count { get; private set; }
    }
}