using CryptographyHelpers.Encoding;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using Microsoft.AspNet.Cryptography.KeyDerivation;
using System;
using System.Diagnostics.CodeAnalysis;

namespace CryptographyHelpers.KeyDerivation
{
    public abstract class PBKDF2Base : IPBKDF2
    {
        private const EncodingType DefaultEncodingType = EncodingType.Base64;
        private readonly KeyDerivationPrf _pseudoRandomFunction;
        private readonly int _iterations;
        private readonly ServiceLocator _serviceLocator = ServiceLocator.Instance;

        public PBKDF2Base(KeyDerivationPrf pseudoRandomFunction, int iterations)
        {
            _pseudoRandomFunction = pseudoRandomFunction;
            _iterations = iterations;
        }


        [ExcludeFromCodeCoverage]
        public PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested) =>
            DeriveKey(password, bytesRequested, salt: null, outputEncodingType: DefaultEncodingType);

        [ExcludeFromCodeCoverage]
        public PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested, byte[] salt) =>
            DeriveKey(password, bytesRequested, salt, outputEncodingType: DefaultEncodingType);

        public PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested, byte[] salt, EncodingType outputEncodingType)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                return new PBKDF2KeyDerivationResult()
                {
                    Success = false,
                    Message = MessageStrings.KeyDerivation_PasswordRequired,
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
                salt = Common.GenerateSalt();
            }

            try
            {
                var derivedKey = Microsoft.AspNet.Cryptography.KeyDerivation.KeyDerivation.Pbkdf2(
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
                    Message = $"{MessageStrings.KeyDerivation_ExceptionError}\n{ex}",
                };
            }
        }
    }
}