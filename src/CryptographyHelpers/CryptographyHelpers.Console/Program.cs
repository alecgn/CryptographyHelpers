using CryptographyHelpers.Encryption.Symmetric.AES.AEAD;
using CryptographyHelpers.Extensions;

namespace CryptographyHelpers.Console
{
    class Program
    {
        static void Main(string[] args)
        {
            //System.Console.WriteLine($"Hello from {nameof(CryptographyHelpers)}!");
            var AESGCM = new AESGGMBase(Common.Generate256BitKey());
            var encryptionResult = AESGCM.Encrypt("teste".ToUTF8Bytes());
            var decryptionResult = AESGCM.Decrypt(encryptionResult.EncryptedData, encryptionResult.Nonce,
                encryptionResult.Tag);
            System.Console.WriteLine(decryptionResult.DecryptedData.ToUTF8String());
        }
    }
}