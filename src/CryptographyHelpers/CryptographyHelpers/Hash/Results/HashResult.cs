using CryptographyHelpers.Encoding;
using CryptographyHelpers.Results;
using System.Security.Authentication;

namespace CryptographyHelpers.Hash
{
    public class HashResult : BaseResult
    {
        public HashAlgorithmType HashAlgorithmType { get; set; }
        public byte[] HashBytes { get; set; }
        public string HashString { get; set; }
        public EncodingType HashStringEncodingType { get; set; }
    }
}