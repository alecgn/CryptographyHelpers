namespace CryptographyHelpers
{
    public class IntPositionOptions
    {
        public IntPositionOptions()
        {
            Offset = 0;
            Count = 0;
        }

        public IntPositionOptions(int offset, int count)
        {
            Offset = offset;
            Count = count;
        }

        public int Offset { get; private set; }

        public int Count { get; private set; }
    }
}