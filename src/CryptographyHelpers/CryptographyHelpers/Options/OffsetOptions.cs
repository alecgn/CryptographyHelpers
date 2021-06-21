namespace CryptographyHelpers.Options
{
    public struct OffsetOptions
    {
        public OffsetOptions(int offset = 0, int count = 0)
        {
            Offset = offset;
            Count = count;
        }

        public int Offset { get; private set; }

        public int Count { get; private set; }
    }
}