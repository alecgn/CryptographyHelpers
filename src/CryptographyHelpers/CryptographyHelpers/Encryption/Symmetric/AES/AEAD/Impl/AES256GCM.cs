using CryptographyHelpers.Resources;
using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AES256GCM : AESGGMBase
    {
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize256Bits;


        public AES256GCM() : base(keySizeToGenerateRandomKey: AESKeySize) { }

        public AES256GCM(byte[] key) : base(key)
        {
            CryptographyCommon.ValidateAESKey(expectedAesKeySize: AESKeySize, key);
        }
    }
}