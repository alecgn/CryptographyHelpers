namespace CryptographyHelpers.Options
{
    public class SeekOptions
    {
        public SeekOptions()
        {
            Offset = 0;
            Count = 0;
        }

        public SeekOptions(int offset, int count)
        {
            Offset = offset;
            Count = count;
        }

        public int Offset { get; private set; }

        public int Count { get; private set; }
    }
}