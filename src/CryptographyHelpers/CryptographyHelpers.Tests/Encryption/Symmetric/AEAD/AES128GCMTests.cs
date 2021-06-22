//using CryptographyHelpers.Encryption.Symmetric.AES.AEAD;
//using CryptographyHelpers.IoC;
//using CryptographyHelpers.Text.Encoding;
//using Microsoft.VisualStudio.TestTools.UnitTesting;
//using System;

//namespace CryptographyHelpers.Tests.Encryption.Symmetric.AEAD
//{
//    [TestClass]
//    public class AES128GCMTests
//    {
//        private const string PlainTestString = "This is a test string!";

//        private readonly IAESGCM _aesGcm;
//        private const string _associatedData = "aa20ca0f-ae3f-4a8b-86f2-e1685342823d";

//        public AES128GCMTests()
//        {
//            _aesGcm = InternalServiceLocator.Instance.GetService<IAES128GCM>();
//        }

//        [TestMethod]
//        [DataRow(EncodingType.Base64, null)]
//        [DataRow(EncodingType.Base64, _associatedData)]
//        [DataRow(EncodingType.Hexadecimal, null)]
//        [DataRow(EncodingType.Hexadecimal, _associatedData)]
//        public void ShouldEncryptAndDecryptTextSucessfully(EncodingType encryptedTextEncodingType, string associatedData)
//        {
//            var encryptionResult = _aesGcm.EncryptText(PlainTestString, encryptedTextEncodingType, associatedData);

//            if (encryptionResult.Success)
//            {
//                var decryptionResult = _aesGcm.DecryptText(encryptionResult.EncryptedDataString, encryptedTextEncodingType, associatedData);
//            }

//        }
//    }
//}
