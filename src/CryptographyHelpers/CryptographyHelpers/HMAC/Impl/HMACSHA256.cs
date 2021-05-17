using CryptographyHelpers.Resources;
using System.Linq;

namespace CryptographyHelpers.HMAC
{
    public class HMACSHA256 : HMACBase
    {
        private const HMACAlgorithmType HMACAlgorithm = HMACAlgorithmType.HMACSHA256;

        public HMACSHA256() : base(HMACAlgorithm) { }

        public new HMACResult ComputeHMAC(byte[] bytesToComputeHMAC, SeekOptions seekOptions, byte[] key = null) =>
            base.ComputeHMAC(bytesToComputeHMAC, seekOptions, key);

        public new HMACResult ComputeHMAC(string stringToComputeHMAC, SeekOptions seekOptions, byte[] key = null) =>
            base.ComputeHMAC(stringToComputeHMAC, seekOptions, key);

        public new HMACResult ComputeFileHMAC(string filePathToComputeHMAC, LongSeekOptions seekOptions, byte[] key = null) =>
            base.ComputeFileHMAC(filePathToComputeHMAC, seekOptions, key);

        public new HMACResult VerifyHMAC(byte[] hmacBytes, byte[] bytesToVerifyHMAC, SeekOptions seekOptions, byte[] key)
        {
            var hmacResult = ComputeHMAC(bytesToVerifyHMAC, seekOptions, key);

            if (hmacResult.Success)
            {
                var hashesMatch = hmacResult.HashBytes.SequenceEqual(hmacBytes);

                hmacResult.Success = hashesMatch;
                hmacResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hmacResult;
        }

        public new HMACResult VerifyHMAC(string hmacHexString, string stringToVerifyHMAC, SeekOptions seekOptions, byte[] key)
        {
            var hmacBytes = Encoding.Hexadecimal.ToByteArray(hmacHexString);
            var stringToVerifyHMACBytes = System.Text.Encoding.UTF8.GetBytes(stringToVerifyHMAC);

            return VerifyHMAC(hmacBytes, stringToVerifyHMACBytes, seekOptions, key);
        }

        public new HMACResult VerifyFileHMAC(string hmacHexString, string filePathToVerifyHMAC, LongSeekOptions seekOptions, byte[] key)
        {
            var hmacBytes = Encoding.Hexadecimal.ToByteArray(hmacHexString);

            return VerifyFileHMAC(hmacBytes, filePathToVerifyHMAC, seekOptions, key);
        }

        public new HMACResult VerifyFileHMAC(byte[] hmacBytes, string filePathToVerifyHMAC, LongSeekOptions seekOptions, byte[] key)
        {
            var hmacResult = ComputeFileHMAC(filePathToVerifyHMAC, seekOptions, key);

            if (hmacResult.Success)
            {
                var hashesMatch = hmacResult.HashBytes.SequenceEqual(hmacBytes);

                hmacResult.Success = hashesMatch;
                hmacResult.Message = $"{(hashesMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return hmacResult;
        }
    }
}
