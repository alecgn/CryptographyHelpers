using CryptographyHelpers.Encoding;
using CryptographyHelpers.Encryption.Symmetric.AES;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptographyHelpers
{
    public static class CryptographyCommon
    {
        private static readonly ServiceLocator _serviceLocator = ServiceLocator.Instance;

        public static byte[] GenerateRandomBytes(int length)
        {
            var randomBytes = new byte[length];
            RandomNumberGenerator.Fill(randomBytes);

            return randomBytes;
        }

        public static byte[] GenerateRandom128BitsKey() =>
            GenerateRandomBytes(128 / Constants.BitsPerByte);

        public static byte[] GenerateRandom192BitsKey() =>
            GenerateRandomBytes(192 / Constants.BitsPerByte);

        public static byte[] GenerateRandom256BitsKey() =>
            GenerateRandomBytes(256 / Constants.BitsPerByte);

        public static byte[] GenerateSalt(int saltLength = 0) =>
        saltLength == 0 ? GenerateRandom128BitsKey() : GenerateRandomBytes(saltLength);

        public static void ClearFileAttributes(string filePath)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"{MessageStrings.File_PathNotFound} {filePath}.", nameof(filePath));
            }

            File.SetAttributes(filePath, FileAttributes.Normal);
        }


        public static void AppendDataBytesToFile(string filePath, byte[] dataBytes)
        {
            using (var fs = File.Open(filePath, FileMode.Append, FileAccess.Write, FileShare.None))
            {
                fs.Write(dataBytes, 0, dataBytes.Length);
            }
        }

        public static byte[] GetBytesFromFile(string filePath, int dataLength, long offset = 0)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"{MessageStrings.File_PathNotFound} {filePath}.", filePath);
            }

            if (dataLength < 1)
            {
                throw new ArgumentException($"Invalid data length: ({dataLength}).", nameof(dataLength));
            }

            var dataBytes = new byte[dataLength];

            using (var fStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                fStream.Seek(offset, SeekOrigin.Begin);
                fStream.Read(dataBytes, 0, dataLength);
                fStream.Close();
            }

            return dataBytes;
        }

        public static bool TagsMatch(byte[] calcTag, byte[] sentTag)
        {
            if (calcTag.Length != sentTag.Length)
            {
                throw new ArgumentException(MessageStrings.Authentication_InvalidTag);
            }

            var result = true;
            var compare = 0;

            for (var i = 0; i < sentTag.Length; i++)
            {
                compare |= sentTag[i] ^ calcTag[i];
            }

            if (compare != 0)
            {
                result = false;
            }

            return result;
        }

        public static string EncodeBytesToString(EncodingType encodingType, byte[] bytes) =>
            encodingType == EncodingType.Base64
            ? _serviceLocator.GetService<IBase64>().EncodeToString(bytes)
            : _serviceLocator.GetService<IHexadecimal>().EncodeToString(bytes);

        public static void ValidateAESKey(AESKeySizes expectedAesKeySize, byte[] key)
        {
            if (key is null || key.Length != (int)expectedAesKeySize / Constants.BitsPerByte)
            {
                throw new ArgumentException($"{MessageStrings.Cryptography_InvalidKey}", nameof(key));
            }
        }
    }
}
