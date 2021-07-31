using CryptographyHelpers.IoC;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AES128GCM : AESGCMBase, IAES128GCM
    {
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize128Bits;
        private const EncodingType DefaultEncodingType = EncodingType.Base64;
        private static readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;


        public AES128GCM() : base(keySizeToGenerateRandomKey: AESKeySize, DefaultEncodingType) { }

        public AES128GCM(byte[] key) : base(ValidateAESKey(key).Invoke(), DefaultEncodingType) { }

        public AES128GCM(string encodedKey, EncodingType? encodingType = null)
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
                    EncodingType.Base64 => _serviceLocator.GetService<IBase64Encoder>().DecodeString(encodedKey),
                    EncodingType.Hexadecimal => _serviceLocator.GetService<IHexadecimalEncoder>().DecodeString(encodedKey),
                    _ => throw new InvalidOperationException($@"Unexpected enum value ""{encodingType}"" of type {typeof(EncodingType)}."),
                };

                CryptographyUtils.ValidateAESKey(key, AESKeySize);

                return key;
            }

            return func;
        }
    }
}