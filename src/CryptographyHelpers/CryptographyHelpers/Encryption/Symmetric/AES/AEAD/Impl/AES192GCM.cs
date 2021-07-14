using CryptographyHelpers.Utils;
using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AES192GCM : AESGCMBase, IAES192GCM
    {
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize192Bits;


        public AES192GCM() : base(keySizeToGenerateRandomKey: AESKeySize) { }

        public AES192GCM(byte[] key) : base(ValidateAESKey(key).Invoke()) { }


        private static Func<byte[]> ValidateAESKey(byte[] key)
        {
            byte[] func()
            {
                CryptographyUtils.ValidateAESKey(key, AESKeySize);

                return key;
            }

            return func;
        }
    }
}