using CryptographyHelpers.Text.Encoding;

namespace CryptographyHelpers.KeyDerivation
{
    public interface IPBKDF2
    {
        PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested);

        PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested, byte[] salt);

        PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested, byte[] salt, EncodingType outputEncodingType);

        PBKDF2KeyDerivationResult VerifyKey(string password, byte[] key, byte[] salt);

        PBKDF2KeyDerivationResult VerifyKey(string password, byte[] key, byte[] salt, EncodingType outputEncodingType);
    }
}