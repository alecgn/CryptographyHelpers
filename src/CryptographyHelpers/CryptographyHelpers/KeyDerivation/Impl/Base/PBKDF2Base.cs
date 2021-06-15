using CryptographyHelpers.Encoding;
using CryptographyHelpers.Extensions;
using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace CryptographyHelpers.KeyDerivation
{
    public abstract class PBKDF2Base : IPBKDF2
    {
        private readonly PseudoRandomFunction _pseudoRandomFunction;
        private readonly int _iterationCount;
        private readonly ServiceLocator _serviceLocator = ServiceLocator.Instance;

        public PBKDF2Base(PseudoRandomFunction pseudoRandomFunction, int iterationCount)
        {
            _pseudoRandomFunction = pseudoRandomFunction;
            _iterationCount = iterationCount;
        }


        [ExcludeFromCodeCoverage]
        public PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested) =>
            DeriveKey(password, bytesRequested, salt: null);


        public PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested, byte[] salt)
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

            KeyDerivationPrf pseudoRandomFunction;

            try
            {
                pseudoRandomFunction = _pseudoRandomFunction.Cast<PseudoRandomFunction, KeyDerivationPrf>();
            }
            catch
            {
                throw new CryptographicException($"{nameof(PseudoRandomFunction)}.{_pseudoRandomFunction} not supported.");
            }

            try
            {
                var derivedKey = Microsoft.AspNetCore.Cryptography.KeyDerivation.KeyDerivation.Pbkdf2(
                    password,
                    salt,
                    pseudoRandomFunction,
                    _iterationCount,
                    bytesRequested);

                return new PBKDF2KeyDerivationResult()
                {
                    Success = true,
                    Message = MessageStrings.KeyDerivation_DerivationSuccess,
                    DerivedKeyBase64String = _serviceLocator.GetService<IBase64>().EncodeToString(derivedKey),
                    DerivedKeyBytes = derivedKey,
                    Salt = salt,
                    PseudoRandomFunction = _pseudoRandomFunction,
                    IterationCount = _iterationCount,
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