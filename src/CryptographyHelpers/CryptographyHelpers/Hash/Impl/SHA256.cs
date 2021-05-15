using CryptographyHelpers.Encoding;

namespace CryptographyHelpers.Hash
{
    public class SHA256 : HashBase, IHash
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.SHA256;

        public SHA256() : base(HashAlgorithm) { }

        public new GenericHashResult ComputeHash(byte[] bytesToComputeHash, SeekOptions seekOptions, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions) =>
            base.ComputeHash(bytesToComputeHash, seekOptions, hexadecimalOutputEncodingOptions);

        public new GenericHashResult ComputeHash(byte[] bytesToComputeHash) =>
            base.ComputeHash(bytesToComputeHash);

        public new GenericHashResult ComputeHash(string stringToComputeHash, SeekOptions seekOptions, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions) =>
            base.ComputeHash(stringToComputeHash, seekOptions, hexadecimalOutputEncodingOptions);

        public new GenericHashResult ComputeHash(string stringToComputeHash) =>
            base.ComputeHash(stringToComputeHash);

        public new GenericHashResult ComputeFileHash(string fileToComputeHash, LongSeekOptions seekOptions, HexadecimalEncodingOptions hexadecimalOutputEncodingOptions) =>
                base.ComputeFileHash(fileToComputeHash, seekOptions, hexadecimalOutputEncodingOptions);

        public new GenericHashResult ComputeFileHash(string fileToComputeHash) =>
            base.ComputeFileHash(fileToComputeHash);

        public new GenericHashResult VerifyHash(byte[] verificationHashBytes, byte[] bytesToVerifyHash) =>
            base.VerifyHash(verificationHashBytes, bytesToVerifyHash);

        public new GenericHashResult VerifyHash(string verificationHexadecimalHashString, string stringToVerifyHash) =>
            base.VerifyHash(verificationHexadecimalHashString, stringToVerifyHash);

        public new GenericHashResult VerifyFileHash(string verificationHexadecimalHashString, string fileToVerifyHash) =>
            base.VerifyFileHash(verificationHexadecimalHashString, fileToVerifyHash);

        public new GenericHashResult VerifyFileHash(byte[] verificationHashBytes, string fileToVerifyHash) =>
            base.VerifyFileHash(verificationHashBytes, fileToVerifyHash);
    }
}