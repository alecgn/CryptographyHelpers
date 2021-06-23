﻿using CryptographyHelpers.Utils;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AES256GCM : AESGCMCore, IAES256GCM
    {
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize256Bits;


        public AES256GCM() : base(keySizeToGenerateRandomKey: AESKeySize) { }

        public AES256GCM(byte[] key) : base(key, AESKeySize) { }
    }
}