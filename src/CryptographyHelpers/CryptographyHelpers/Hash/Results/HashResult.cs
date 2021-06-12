using CryptographyHelpers.Encoding;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.Hash
{
    [ExcludeFromCodeCoverage]
    public class HashResult
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public HashAlgorithmType HashAlgorithmType { get; set; }
        public EncodingType OutputEncodingType { get; set; }
        public byte[] HashBytes { get; set; }
        public string HashString { get; set; }
    }
}