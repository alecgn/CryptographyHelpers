using CryptographyHelpers.IoC;
using CryptographyHelpers.Text.Encoding;
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
        private const EncodingType DefaultEncodingType = EncodingType.Base64;
        private static readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;


        public AES128CBC() : base(AESKeySize, Mode, Padding, DefaultEncodingType) { }

        public AES128CBC(byte[] key, byte[] IV)
            : base(ValidateAESKey(key).Invoke(), ValidateAESIV(IV).Invoke(), Mode, Padding, DefaultEncodingType) { }

        public AES128CBC(string encodedKey, string encodedIV, EncodingType? encodingType = null)
            : base(
                  ValidateEncodedAESKey(encodedKey, encodingType ?? DefaultEncodingType).Invoke(),
                  ValidateEncodedAESIV(encodedIV, encodingType ?? DefaultEncodingType).Invoke(),
                  Mode,
                  Padding,
                  encodingType ?? DefaultEncodingType)
        { }


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

        private static Func<byte[]> ValidateAESIV(byte[] IV)
        {
            byte[] func()
            {
                CryptographyUtils.ValidateAESIV(IV);

                return IV;
            }

            return func;
        }

        private static Func<byte[]> ValidateEncodedAESIV(string encodedIV, EncodingType encodingType)
        {
            byte[] func()
            {
                var IV = encodingType switch
                {
                    EncodingType.Base64 => _serviceLocator.GetService<IBase64Encoder>().DecodeString(encodedIV),
                    EncodingType.Hexadecimal => _serviceLocator.GetService<IHexadecimalEncoder>().DecodeString(encodedIV),
                    _ => throw new InvalidOperationException($@"Unexpected enum value ""{encodingType}"" of type {typeof(EncodingType)}."),
                };

                CryptographyUtils.ValidateAESIV(IV);

                return IV;
            }

            return func;
        }
    }
}