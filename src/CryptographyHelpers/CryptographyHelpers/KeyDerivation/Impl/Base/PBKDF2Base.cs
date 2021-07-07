using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Linq;

namespace CryptographyHelpers.KeyDerivation
{
    public abstract class PBKDF2Base : IPBKDF2
    {
        private const EncodingType DefaultEncodingType = EncodingType.Base64;
        private readonly KeyDerivationPrf _pseudoRandomFunction;
        private readonly int _iterations;
        private readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;

        public PBKDF2Base(KeyDerivationPrf pseudoRandomFunction, int iterations)
        {
            _pseudoRandomFunction = pseudoRandomFunction;
            _iterations = iterations;
        }


        public PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested) =>
            DeriveKey(password, bytesRequested, salt: null, outputEncodingType: DefaultEncodingType);

        public PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested, byte[] salt) =>
            DeriveKey(password, bytesRequested, salt, outputEncodingType: DefaultEncodingType);

        public PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested, byte[] salt, EncodingType outputEncodingType)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return new PBKDF2KeyDerivationResult()
                {
                    Success = false,
                    Message = MessageStrings.KeyDerivation_PasswordStringRequired,
                };
            }

            if (bytesRequested <= 0)
            {
                return new PBKDF2KeyDerivationResult()
                {
                    Success = false,
                    Message = MessageStrings.KeyDerivation_InvalidBytesRequested,
                };
            }

            if (salt is null || salt.Length == 0)
            {
                salt = CryptographyUtils.GenerateSalt();
            }

            try
            {
                var derivedKey = Microsoft.AspNetCore.Cryptography.KeyDerivation.KeyDerivation.Pbkdf2(
                    password,
                    salt,
                    _pseudoRandomFunction,
                    _iterations,
                    bytesRequested);

                return new PBKDF2KeyDerivationResult()
                {
                    Success = true,
                    Message = MessageStrings.KeyDerivation_DerivationSuccess,
                    OutputEncodingType = outputEncodingType,
                    DerivedKeyString = outputEncodingType == EncodingType.Base64
                        ? _serviceLocator.GetService<IBase64>().EncodeToString(derivedKey)
                        : _serviceLocator.GetService<IHexadecimal>().EncodeToString(derivedKey),
                    DerivedKeyBytes = derivedKey,
                    Salt = salt,
                    PseudoRandomFunction = _pseudoRandomFunction,
                    Iterations = _iterations,
                };
            }
            catch (Exception ex)
            {
                return new PBKDF2KeyDerivationResult()
                {
                    Success = false,
                    Message = ex.ToString(),
                };
            }
        }


        public PBKDF2KeyDerivationResult VerifyKey(string password, byte[] key, byte[] salt) =>
            VerifyKey(password, key, salt, outputEncodingType: DefaultEncodingType);

        public PBKDF2KeyDerivationResult VerifyKey(string password, byte[] key, byte[] salt, EncodingType outputEncodingType)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return new PBKDF2KeyDerivationResult()
                {
                    Success = false,
                    Message = MessageStrings.KeyDerivation_PasswordStringRequired,
                };
            }

            if (key is null || key.Length == 0)
            {
                return new PBKDF2KeyDerivationResult()
                {
                    Success = false,
                    Message = MessageStrings.KeyDerivation_KeyBytesRequired,
                };
            }

            var keyDerivationResult = DeriveKey(password, key.Length, salt, outputEncodingType);

            if (keyDerivationResult.Success)
            {
                var keysMatch = keyDerivationResult.DerivedKeyBytes.SequenceEqual(key);

                keyDerivationResult.Success = keysMatch;
                keyDerivationResult.Message = $"{(keysMatch ? MessageStrings.Hash_Match : MessageStrings.Hash_DoesNotMatch)}";
            }

            return keyDerivationResult;
        }
    }
}