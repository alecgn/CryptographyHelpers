using CryptographyHelpers.Encoding;
using CryptographyHelpers.HMAC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Util;
using CryptographyHelpers.Util.Extensions;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Security.Cryptography;

namespace CryptographyHelpers.KeyDerivation
{
    public abstract class PBKDF2Base : IPBKDF2
    {
        private const int MinimumIterationCount = 10000;
        private HMACAlgorithmType _pseudoRandomFunction;

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
                salt = CryptographyCommon.GenerateSalt();
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
                    DerivedKeyBase64String = Base64.ToBase64String(derivedKey),
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