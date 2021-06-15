namespace CryptographyHelpers.KeyDerivation
{
    public interface IPBKDF2
    {
        PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested);
        PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested, byte[] salt);
    }
}
