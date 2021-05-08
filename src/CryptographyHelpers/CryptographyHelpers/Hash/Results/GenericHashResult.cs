namespace CryptographyHelpers.Hash
{
    public class GenericHashResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public HashAlgorithmType HashAlgorithmType { get; set; }
        public string HashString { get; set; }
        public byte[] HashBytes { get; set; }
    }
}
