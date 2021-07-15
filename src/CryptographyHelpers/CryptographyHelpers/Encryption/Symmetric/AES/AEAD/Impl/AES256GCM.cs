using CryptographyHelpers.IoC;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AES256GCM : AESGCMBase, IAES256GCM
    {
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize256Bits;
        private const EncodingType DefaultEncodingType = EncodingType.Base64;
        private static readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;


        public AES256GCM() : base(keySizeToGenerateRandomKey: AESKeySize, DefaultEncodingType) { }

        public AES256GCM(byte[] key) : base(ValidateAESKey(key).Invoke(), DefaultEncodingType) { }

        public AES256GCM(string encodedKey, EncodingType? encodingType = null)
            : base(ValidateEncodedAESKey(encodedKey, encodingType ?? DefaultEncodingType).Invoke(), encodingType ?? DefaultEncodingType) { }


        private static Func<byte[]> ValidateAESKey(byte[] key)
        {
            byte[] func()
            {
                CryptographyUtils.ValidateAESKey(key, AESKeySize);

                return key;
            }

            return func;
        }

        private static Func<byte[]> ValidateEncodedAESKey(string encodedKey, EncodingType encodingType)
        {
            byte[] func()
            {
                var key = encodingType switch
                {
                    EncodingType.Base64 => _serviceLocator.GetService<IBase64>().DecodeString(encodedKey),
                    EncodingType.Hexadecimal => _serviceLocator.GetService<IHexadecimal>().DecodeString(encodedKey),
                    _ => throw new InvalidOperationException($@"Unexpected enum value ""{encodingType}"" of type {typeof(EncodingType)}."),
                };

                CryptographyUtils.ValidateAESKey(key, AESKeySize);

                return key;
            }

            return func;
        }
    }
}