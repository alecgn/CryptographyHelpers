using CryptographyHelpers.Resources;
using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AESGCM256 : AESGGMBase
    {
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize256Bits;


        public AESGCM256() : base(keySizeToGenerateRandomKey: AESKeySize) { }

        public AESGCM256(byte[] key) : base(key)
        {
            CryptographyCommon.ValidateAESKey(expectedAesKeySize: AESKeySize, key);
        }
    }
}