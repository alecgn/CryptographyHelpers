//namespace CryptographyHelpers.Encryption.Symmetric.AES.AEAD.Impl
//{
//    public class AESGCMTextHandler
//    {
//        private readonly AESGCMAlgorithm _aesGcmMAlgorithm;

//        public AESGCMTextHandler(AESGCMAlgorithm aesGcmMAlgorithm) =>
//            _aesGcmMAlgorithm = aesGcmMAlgorithm;

//public AESGCMEncryptionResult EncryptText(string plainText, EncodingType encryptedTextEncodingType, string associatedData = null)
//{
//    if (string.IsNullOrWhiteSpace(plainText))
//    {
//        return new()
//        {
//            Success = false,
//            Message = MessageStrings.Strings_InvalidInputString,
//        };
//    }

//    var plainTextBytes = plainText.ToUTF8Bytes();
//    var associatedDataBytes = associatedData?.ToUTF8Bytes();

//    var encryptionResult = Encrypt(plainTextBytes, associatedDataBytes);

//    if (encryptionResult.Success)
//    {
//        encryptionResult.EncryptedDataString = encryptedTextEncodingType == EncodingType.Base64
//            ? _serviceLocator.GetService<IBase64>().EncodeToString(encryptionResult.EncryptedData)
//            : _serviceLocator.GetService<IHexadecimal>().EncodeToString(encryptionResult.EncryptedData);
//    }

//    return encryptionResult;
//}

//public AESGCMDecryptionResult DecryptText(string encryptedText, string nonce, string tag, EncodingType inputParametersEncodingType, string associatedData = null)
//{
//    if (string.IsNullOrWhiteSpace(encryptedText))
//    {
//        return new()
//        {
//            Success = false,
//            Message = MessageStrings.Strings_InvalidInputString,
//        };
//    }

//    try
//    {
//        var encryptedTextBytes = inputParametersEncodingType == EncodingType.Base64
//            ? _serviceLocator.GetService<IBase64>().DecodeString(encryptedText)
//            : _serviceLocator.GetService<IHexadecimal>().DecodeString(encryptedText);
//        var nonceBytes = inputParametersEncodingType == EncodingType.Base64
//            ? _serviceLocator.GetService<IBase64>().DecodeString(nonce)
//            : _serviceLocator.GetService<IHexadecimal>().DecodeString(nonce);
//        var tagBytes = inputParametersEncodingType == EncodingType.Base64
//            ? _serviceLocator.GetService<IBase64>().DecodeString(tag)
//            : _serviceLocator.GetService<IHexadecimal>().DecodeString(tag);
//        var associatedDataBytes = associatedData?.ToUTF8Bytes();

//        var decryptionResult = Decrypt(encryptedTextBytes, nonceBytes, tagBytes, associatedDataBytes);

//        if (decryptionResult.Success)
//        {
//            decryptionResult.DecryptedDataString = decryptionResult.DecryptedData.ToUTF8String();
//        }

//        return decryptionResult;
//    }
//    catch (Exception ex)
//    {
//        return new()
//        {
//            Success = false,
//            Message = ex.ToString(),
//        };
//    }
//}
//    }
//}