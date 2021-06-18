using CryptographyHelpers.Resources;
using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AES128GCM : AESGGMBase
    {
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize128Bits;


        public AES128GCM() : base(keySizeToGenerateRandomKey: AESKeySize) { }

        public AES128GCM(byte[] key) : base(key)
        {
            CryptographyCommon.ValidateAESKey(expectedAesKeySize: AESKeySize, key);
        }
    }
}