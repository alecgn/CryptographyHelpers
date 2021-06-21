using CryptographyHelpers.Encryption.Symmetric.AES;
using CryptographyHelpers.Resources;
using System;
using System.Security.Cryptography;

namespace CryptographyHelpers.Utils
{
    public static class CryptographyUtils
    {
        public static byte[] GenerateRandomBytes(int length)
        {
            var randomBytes = new byte[length];
            using var rngCryptoServiceProvider = new RNGCryptoServiceProvider();
            rngCryptoServiceProvider.GetBytes(randomBytes);

            return randomBytes;
        }

        public static byte[] GenerateRandom128BitsKey() =>
            GenerateRandomBytes(128 / Constants.BitsPerByte);

        public static byte[] GenerateRandom192BitsKey() =>
            GenerateRandomBytes(192 / Constants.BitsPerByte);

        public static byte[] GenerateRandom256BitsKey() =>
            GenerateRandomBytes(256 / Constants.BitsPerByte);

        public static byte[] GenerateSalt(int? saltLength = null) =>
            saltLength is null || saltLength == 0 ? GenerateRandom128BitsKey() : GenerateRandomBytes(saltLength.Value);

        public static void ValidateAESKey(AESKeySizes expectedAesKeySize, byte[] key)
        {
            if (key is null || key.Length != (int)expectedAesKeySize / Constants.BitsPerByte)
            {
                throw new ArgumentException($"{MessageStrings.Cryptography_InvalidKey}", nameof(key));
            }
        }
    }
}