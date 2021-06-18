using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AES256CBC : AESBase
    {
        private const CipherMode Mode = CipherMode.CBC;
        private const PaddingMode Padding = PaddingMode.PKCS7;
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize256Bits;

        public AES256CBC(byte[] key, byte[] IV) : base(key, IV, Mode, Padding)
        {
            CryptographyCommon.ValidateAESKey(expectedAesKeySize: AESKeySize, key);
        }
    }
}