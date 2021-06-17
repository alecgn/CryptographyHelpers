using CryptographyHelpers.Encoding;

namespace CryptographyHelpers.KeyDerivation
{
    public interface IPBKDF2
    {
        PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested);
        PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested, byte[] salt);
        PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested, byte[] salt, EncodingType outputEncodingType);
    }
}
