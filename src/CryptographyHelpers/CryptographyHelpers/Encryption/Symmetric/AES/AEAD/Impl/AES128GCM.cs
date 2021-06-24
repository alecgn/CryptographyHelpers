using CryptographyHelpers.Utils;
using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AES128GCM : AESGCMCore, IAES128GCM
    {
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize128Bits;


        public AES128GCM() : base(keySizeToGenerateRandomKey: AESKeySize) { }

        public AES128GCM(byte[] key) : base(ValidateAESKey(key).Invoke()) { }

        
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