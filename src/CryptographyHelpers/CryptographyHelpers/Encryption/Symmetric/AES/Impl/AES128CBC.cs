using CryptographyHelpers.Utils;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AES128CBC : AESBase, IAES128CBC
    {
        private const CipherMode Mode = CipherMode.CBC;
        private const PaddingMode Padding = PaddingMode.PKCS7;
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize128Bits;


        public AES128CBC() : base(keySizeToGenerateRandomKey: AESKeySize) { }

        public AES128CBC(byte[] key, byte[] IV) : base(key, IV, Mode, Padding)
        {
            CryptographyUtils.ValidateAESKey(key, expectedAesKeySize: AESKeySize);
        }
    }
}