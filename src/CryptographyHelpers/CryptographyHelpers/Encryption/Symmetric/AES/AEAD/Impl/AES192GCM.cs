using CryptographyHelpers.Utils;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AES192GCM : AESGCMCore, IAES192GCM
    {
        private const AESKeySizes AESKeySize = AESKeySizes.KeySize192Bits;


        public AES192GCM() : base(keySizeToGenerateRandomKey: AESKeySize) { }

        public AES192GCM(byte[] key) : base(key, AESKeySize) { }
    }
}