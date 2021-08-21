using CryptographyHelpers.IoC;
using CryptographyHelpers.KeyDerivation;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AES128GCM : AESGCMBase, IAES128GCM
    {
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize128Bits;
        private static readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;


        public AES128GCM(EncodingType encodingType = EncodingType.Base64)
            : base(keySizeToGenerateRandomKey: AESKeySize, encodingType) { }

        public AES128GCM(byte[] key, EncodingType encodingType = EncodingType.Base64)
            : base(ValidateAESKey(key).Invoke(), encodingType) { }

        public AES128GCM(string encodedKey, EncodingType encodingType = EncodingType.Base64)
            : base(ValidateEncodedAESKey(encodedKey, encodingType).Invoke(), encodingType) { }

        public AES128GCM(
            string password,
            KeyDerivationPrf keyDerivationFunction = KeyDerivationPrf.HMACSHA1,
            EncodingType encodingType = EncodingType.Base64)
                : base(DeriveAESKeyFromPassword(password, keyDerivationFunction).Invoke(), encodingType) { }


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

        private static Func<byte[]> DeriveAESKeyFromPassword(string password, KeyDerivationPrf keyDerivationFunction)
        {
            byte[] func()
            {
                var derivedKey = keyDerivationFunction switch
                {
                    KeyDerivationPrf.HMACSHA1 => _serviceLocator.GetService<IPBKDF2HMACSHA1>().DeriveKey(password, (int)AESKeySize).DerivedKeyBytes,
                    KeyDerivationPrf.HMACSHA256 => _serviceLocator.GetService<IPBKDF2HMACSHA256>().DeriveKey(password, (int)AESKeySize).DerivedKeyBytes,
                    KeyDerivationPrf.HMACSHA512 => _serviceLocator.GetService<IPBKDF2HMACSHA512>().DeriveKey(password, (int)AESKeySize).DerivedKeyBytes,
                    _ => throw new InvalidOperationException($@"Unexpected enum value ""{keyDerivationFunction}"" of type {typeof(KeyDerivationPrf)}."),
                };

                return derivedKey;
            }

            return func;
        }
    }
}