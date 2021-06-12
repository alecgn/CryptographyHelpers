using CryptographyHelpers.Encoding;
using CryptographyHelpers.Extensions;
using CryptographyHelpers.HMAC;
using CryptographyHelpers.IoC;
using CryptographyHelpers.KeyDerivation.Results;
using CryptographyHelpers.Resources;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Security.Cryptography;

namespace CryptographyHelpers.KeyDerivation
{
    public abstract class PBKDF2Base : IPBKDF2
    {
        private const int MinimumIterationCount = 10000;
        private readonly HMACAlgorithmType _pseudoRandomFunction;
        private readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;

        public PBKDF2Base(HMACAlgorithmType pseudoRandomFunction)
        {
            _pseudoRandomFunction = pseudoRandomFunction;
        }

        public PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested, byte[] salt = null, int iterationCount = MinimumIterationCount)
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

            if (iterationCount < MinimumIterationCount)
            {
                return new PBKDF2KeyDerivationResult()
                {
                    Success = false,
                    Message = string.Format(MessageStrings.KeyDerivation_IterationCountInvalid, MinimumIterationCount),
                };
            }

            if (salt is null || salt.Length == 0)
            {
                salt = Common.GenerateSalt();
            }

            KeyDerivationPrf pseudoRandomFunction;

            try
            {
                pseudoRandomFunction = _pseudoRandomFunction.Cast<HMACAlgorithmType, KeyDerivationPrf>();
            }
            catch
            {
                throw new CryptographicException($"{nameof(HMACAlgorithmType)}.{_pseudoRandomFunction} not supported.");
            }

            try
            {
                var derivedKey = Microsoft.AspNetCore.Cryptography.KeyDerivation.KeyDerivation.Pbkdf2(
                    password,
                    salt,
                    pseudoRandomFunction,
                    iterationCount,
                    bytesRequested);

                return new PBKDF2KeyDerivationResult()
                {
                    Success = true,
                    Message = MessageStrings.KeyDerivation_DerivationSuccess,
                    DerivedKeyBase64String = _serviceLocator.GetService<IBase64>().EncodeToString(derivedKey),
                    DerivedKeyBytes = derivedKey,
                    Salt = salt,
                    PseudoRandomFunction = _pseudoRandomFunction,
                    IterationCount = iterationCount,
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