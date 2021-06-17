using CryptographyHelpers.Resources;
using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AESGCM128 : AESGGMBase
    {
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize128Bits;


        public AESGCM128() : base(keySizeToGenerateRandomKey: AESKeySize) { }

        public AESGCM128(byte[] key) : base(key)
        {
            CryptographyCommon.ValidateAESKey(expectedAesKeySize: AESKeySize, key);
        }
    }
}