using CryptographyHelpers.Utils;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AES192CBC : AESBase, IAES192CBC
    {
        private const CipherMode Mode = CipherMode.CBC;
        private const PaddingMode Padding = PaddingMode.PKCS7;
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize192Bits;

        public AES192CBC(byte[] key, byte[] IV) : base(key, IV, Mode, Padding)
        {
            CryptographyUtils.ValidateAESKey(expectedAesKeySize: AESKeySize, key);
        }
    }
}