namespace CryptographyHelpers.HMAC
{
    public class HMACResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string HashString { get; set; }
        public byte[] HashBytes { get; set; }
        public byte[] Key { get; set; }
        public HMACAlgorithmType HMACAlgorithmType { get; set; }
    }
}
