using CryptographyHelpers.Options;
using CryptographyHelpers.Resources;
using System;
using System.IO;

namespace CryptographyHelpers.Utils
{
    public static class FileUtils
    {
        public static void AppendBytesToFile(string filePath, byte[] bytes)
        {
            using var fileStream = File.Open(filePath, FileMode.Append, FileAccess.Write, FileShare.None);
            fileStream.Write(bytes, 0, bytes.Length);
        }

        public static byte[] GetBytesFromFile(string filePath, OffsetOptions offsetOptions)
        {
            if (!File.Exists(filePath))
            {
                throw new FileNotFoundException($"{MessageStrings.File_PathNotFound} {filePath}.", filePath);
            }

            if (offsetOptions.Count < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(offsetOptions), $"Invalid value of {nameof(OffsetOptions)}.{nameof(OffsetOptions.Count)}: ({offsetOptions.Count}).");
            }

            using var fileStream = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read);
            fileStream.Seek(offsetOptions.Offset, SeekOrigin.Begin);
            var bytes = new byte[offsetOptions.Count];
            fileStream.Read(bytes, 0, offsetOptions.Count);

            return bytes;
        }
    }
}