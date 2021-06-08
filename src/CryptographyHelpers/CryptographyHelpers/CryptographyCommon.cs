using CryptographyHelpers.Encoding;
using CryptographyHelpers.Encoding.Enums;
using CryptographyHelpers.Resources;
using System;
using System.IO;
using System.Security.Cryptography;

namespace CryptographyHelpers
{
    public static class CryptographyCommon
    {
        public static byte[] GenerateRandomBytes(int length)
        {
            var randomBytes = new byte[length];

            using (var rngCSP = new RNGCryptoServiceProvider())
            {
                rngCSP.GetBytes(randomBytes);
            }

            return randomBytes;
        }

        public static byte[] Generate128BitKey() =>
            GenerateRandomBytes(128 / 8);

        public static byte[] GenerateSalt(int saltLength = 0) =>
        saltLength == 0 ? Generate128BitKey() : GenerateRandomBytes(saltLength);

        public static byte[] Generate256BitKey() =>
            GenerateRandomBytes(256 / 8);

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
            encodingType == EncodingType.Base64 ? Base64.EncodeToString(bytes) : Hexadecimal.EncodeToString(bytes);
    }
}
