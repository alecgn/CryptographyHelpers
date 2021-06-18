using CryptographyHelpers.Resources;
using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AES192GCM : AESGGMBase
    {
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize192Bits;


        public AES192GCM() : base(keySizeToGenerateRandomKey: AESKeySize) { }

        public AES192GCM(byte[] key) : base(key)
        {
            CryptographyCommon.ValidateAESKey(expectedAesKeySize: AESKeySize, key);
        }
    }
}