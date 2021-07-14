using CryptographyHelpers.Utils;
using System;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AES128CBC : AESBase, IAES128CBC
    {
        private const CipherMode Mode = CipherMode.CBC;
        private const PaddingMode Padding = PaddingMode.PKCS7;
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize128Bits;


        public AES128CBC() : base(keySizeToGenerateRandomKey: AESKeySize) { }

        public AES128CBC(byte[] key, byte[] IV)
            : base(ValidateAESKey(key).Invoke(), ValidateAESIV(IV).Invoke(), Mode, Padding) { }


        private static Func<byte[]> ValidateAESKey(byte[] key)
        {
            byte[] func()
            {
                CryptographyUtils.ValidateAESKey(key, AESKeySize);

                return key;
            }

            return func;
        }

        private static Func<byte[]> ValidateAESIV(byte[] IV)
        {
            byte[] func()
            {
                CryptographyUtils.ValidateAESIV(IV);

                return IV;
            }

            return func;
        }
    }
}