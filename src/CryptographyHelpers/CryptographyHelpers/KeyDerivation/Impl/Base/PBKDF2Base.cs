using CryptographyHelpers.IoC;
using CryptographyHelpers.Resources;
using CryptographyHelpers.Text.Encoding;
using CryptographyHelpers.Utils;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;

namespace CryptographyHelpers.KeyDerivation
{
    public class PBKDF2Base : IPBKDF2
    {
        private readonly EncodingType _encodingType = EncodingType.Base64;
        private readonly IEncoder _encoder;
        private readonly KeyDerivationPrf _pseudoRandomFunction;
        private readonly int _iterations;
        private readonly byte[] _salt;
        private readonly InternalServiceLocator _serviceLocator = InternalServiceLocator.Instance;


        public PBKDF2Base(KeyDerivationPrf pseudoRandomFunction, int iterations, byte[] salt = null, EncodingType? encodingType = null)
        {
            _pseudoRandomFunction = pseudoRandomFunction;
            _iterations = iterations;
            _encodingType = encodingType ?? _encodingType;
            _encoder = _encodingType switch
            {
                EncodingType.Hexadecimal => _serviceLocator.GetService<IHexadecimalEncoder>(),
                EncodingType.Base64 => _serviceLocator.GetService<IBase64Encoder>(),
                _ => throw new InvalidOperationException($@"Unexpected enum value ""{_encodingType}"" of type {typeof(EncodingType)}."),
            };
            _salt = salt ?? CryptographyUtils.GenerateSalt();
        }


        public PBKDF2KeyDerivationResult DeriveKey(string password, int bytesRequested)
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

            try
            {
                var derivedKey = Microsoft.AspNetCore.Cryptography.KeyDerivation.KeyDerivation.Pbkdf2(
                    password,
                    _salt,
                    _pseudoRandomFunction,
                    _iterations,
                    bytesRequested);

                return new PBKDF2KeyDerivationResult()
                {
                    Success = true,
                    Message = MessageStrings.KeyDerivation_DerivationSuccess,
                    OutputEncodingType = _encodingType,
                    DerivedKeyString = _encoder.EncodeToString(derivedKey),
                    DerivedKeyBytes = derivedKey,
                    Salt = _salt,
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
    }
}