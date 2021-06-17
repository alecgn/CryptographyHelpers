namespace CryptographyHelpers.Encryption.Symmetric.AES
{
    public enum AESImplementation
    { 
        AESGCM128, 
        AESGCM192, 
        AESGCM256,
        AESCBC128HMACSHA256,
        AESCBC192HMACSHA384,
        AESCBC256HMACSHA384,
        AESCBC256HMACSHA512,
    }
}