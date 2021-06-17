using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD
{
    public class AESGGMBase
    {
        private const int NonceLength = 12;
        private const int TagLength = 16;
        private readonly byte[] _key;

        public AESGGMBase(byte[] key) => 
            _key = key;

        public AESGCMEncryptionResult Encrypt(byte[] data, byte[] nonce = null, byte[] associatedData = null)
        {
            if (data == null || data.Length == 0)
            {
                return new()
                {
                    Success = false,
                    Message = "MessageStrings.Encryption_InputRequired",
                };
            }

            if (nonce == null || nonce.Length == 0)
            {
                nonce = Common.GenerateRandomBytes(NonceLength);
            }
            else
            {
                if (!IsValidNonceSize(nonce.Length))
                {
                    return new()
                    {
                        Success = false,
                        Message = "MessageStrings.Encryption_InputRequired",
                    };
                }
            }

            var encryptedData = new byte[data.Length];
            var tag = new byte[TagLength];

            try
            {
                using (var aesGcm = new AesGcm(_key))
                {
                    aesGcm.Encrypt(nonce, data, encryptedData, tag, associatedData);
                    var teste = AesGcm.NonceByteSizes;
                    var teste2 = AesGcm.TagByteSizes;

                }

                return new()
                {
                    Success = true,
                    Message = "MessageStrings.Encryption_EncryptSuccess",
                    EncryptedData = encryptedData,
                    Key = _key,
                    Nonce = nonce,
                    Tag = tag,
                };
            }
            catch (Exception ex)
            {
                return new()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        public AESGCMDecryptionResult Decrypt(byte[] encryptedData, byte[] nonce, byte[] tag, byte[] associatedData = null)
        {
            if (encryptedData == null || encryptedData.Length == 0)
            {
                return new()
                {
                    Success = false,
                    Message = "MessageStrings.Decryption_InputRequired",
                };
            }

            if (nonce == null || nonce.Length == 0)
            {
                return new()
                {
                    Success = false,
                    Message = "MessageStrings.Decryption_InputRequired",
                };
            }

            if (tag == null || tag.Length == 0)
            {
                return new()
                {
                    Success = false,
                    Message = "MessageStrings.Decryption_InputRequired",
                };
            }

            var decryptedData = new byte[encryptedData.Length];

            try
            {
                using (AesGcm aesGcm = new(_key))
                {
                    aesGcm.Decrypt(nonce, encryptedData, tag, decryptedData, associatedData);
                }

                return new()
                {
                    Success = true,
                    Message = "MessageStrings.Encryption_EncryptSuccess",
                    DecryptedData = decryptedData,
                    Key = _key,
                    Nonce = nonce,
                    Tag = tag,
                };

            }
            catch (Exception ex)
            {
                return new()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }

        private bool IsValidNonceSize(int nonceSize)
        {
            List<int> allowedNonceSizes = new();

            for (var tmpNonceSize = AesGcm.NonceByteSizes.MinSize; tmpNonceSize < AesGcm.NonceByteSizes.MaxSize; tmpNonceSize += AesGcm.NonceByteSizes.SkipSize)
            {
                allowedNonceSizes.Add(tmpNonceSize);
            }

            return allowedNonceSizes.Contains(nonceSize);
        }
    }
}