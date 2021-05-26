namespace CryptographyHelpers.Options
{
    public class LongSeekOptions
    {
        public LongSeekOptions()
        {
            Offset = 0L;
            Count = 0L;
        }

        public LongSeekOptions(long offset, long count)
        {
            Offset = offset;
            Count = count;
        }

        public long Offset { get; private set; }

        public long Count { get; private set; }
    }
}