using CryptographyHelpers.Results;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AESBaseResult : BaseResult
    {
        public byte[] Key { get; set; }
    }
}