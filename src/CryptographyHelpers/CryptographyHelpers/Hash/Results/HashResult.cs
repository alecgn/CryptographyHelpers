using CryptographyHelpers.Results;
using CryptographyHelpers.Text.Encoding;
using System.Security.Authentication;

namespace CryptographyHelpers.Hash
{
    public class HashResult : BaseResult
    {
        public HashAlgorithmType HashAlgorithmType { get; set; }
        public byte[] HashBytes { get; set; }
        public EncodingType EncodingType { get; set; }
        public string HashString { get; set; }
    }
}