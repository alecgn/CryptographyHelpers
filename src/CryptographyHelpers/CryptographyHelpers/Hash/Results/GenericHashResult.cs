using CryptographyHelpers.Encoding.Enums;
using CryptographyHelpers.Hash.Enums;

namespace CryptographyHelpers.Hash.Results
{
    public class GenericHashResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public HashAlgorithmType HashAlgorithmType { get; set; }
        public EncodingType OutputEncodingType { get; set; }
        public byte[] HashBytes { get; set; }
        public string HashString { get; set; }
    }
}