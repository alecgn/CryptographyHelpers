using CryptographyHelpers.Resources;
using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AESGCM192 : AESGGMBase
    {
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize192Bits;


        public AESGCM192() : base(keySizeToGenerateRandomKey: AESKeySize) { }

        public AESGCM192(byte[] key) : base(key)
        {
            CryptographyCommon.ValidateAESKey(expectedAesKeySize: AESKeySize, key);
        }
    }
}