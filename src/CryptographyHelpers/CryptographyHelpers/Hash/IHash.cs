namespace CryptographyHelpers.Hash
{
    public interface IHash
    {
        GenericHashResult ComputeHash(byte[] bytesToComputeHash, int offset = 0, int count = 0);

        GenericHashResult ComputeHash(string stringToComputeHash, int offset = 0, int count = 0);

        GenericHashResult ComputeFileHash(string filePathToComputeHash, long offset = 0, long count = 0);

        GenericHashResult VerifyHash(byte[] hashBytes, byte[] bytesToVerifyHash, int offset = 0, int count = 0);

        GenericHashResult VerifyHash(string hashHexString, string stringToVerifyHash, int offset = 0, int count = 0);

        GenericHashResult VerifyFileHash(string hashHexString, string filePathToVerifyHash, long offset = 0, long count = 0);

        GenericHashResult VerifyFileHash(byte[] hashBytes, string filePathToVerifyHash, long offset = 0, long count = 0);
    }
}
