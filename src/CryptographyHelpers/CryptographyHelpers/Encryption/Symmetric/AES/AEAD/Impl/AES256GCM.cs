using CryptographyHelpers.Utils;
using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AES256GCM : AESGCMBase, IAES256GCM
    {
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize256Bits;


        public AES256GCM() : base(keySizeToGenerateRandomKey: AESKeySize) { }

        public AES256GCM(byte[] key) : base(ValidateAESKey(key).Invoke()) { }


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