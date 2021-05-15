namespace CryptographyHelpers.KeyDerivation
{
    public interface IPBKDF2
    {
        const int MinimumIterationCount = 10000;

        PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested, byte[] salt = null, int iterationCount = MinimumIterationCount);
    }
}
