using CryptographyHelpers.Utils;
using System;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public class AES256CBC : AESCore, IAES256CBC
    {
        private const CipherMode Mode = CipherMode.CBC;
        private const PaddingMode Padding = PaddingMode.PKCS7;
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize256Bits;


        public AES256CBC() : base(keySizeToGenerateRandomKey: AESKeySize) { }

        public AES256CBC(byte[] key, byte[] IV)
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