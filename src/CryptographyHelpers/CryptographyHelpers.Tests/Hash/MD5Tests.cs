//using CryptographyHelpers.Hash;
//using Microsoft.VisualStudio.TestTools.UnitTesting;

//namespace CryptographyHelpers.Tests.Hash
//{
//    [TestClass]
//    public class MD5Tests
//    {
//        private readonly MD5 _md5 = new();
//        private readonly string _testString = "This is a test string!";

//        [TestMethod]
//        public void ComputeAndVerifyHash_String()
//        {
//            var verifyResult = new GenericHashResult();
//            var errorMessage = "";

//            var hashResult = _md5.ComputeHash(_testString);

//            if (hashResult.Success)
//            {
//                verifyResult = _md5.VerifyHash(hashResult.HashString, _testString);

//                if (!verifyResult.Success)
//                {
//                    errorMessage = verifyResult.Message;
//                }
//            }
//            else
//            {
//                errorMessage = hashResult.Message;
//            }

//            Assert.IsTrue((hashResult.Success && verifyResult.Success), errorMessage);
//        }

//        [TestMethod]
//        public void ComputeAndVerifyHash_File()
//        {
//            var testFilePath = Path.GetTempFileName();
//            var verifyResult = new GenericHashResult();
//            var errorMessage = "";

//            File.WriteAllText(testFilePath, _testString);

//            var hashResult = _md5.ComputeFileHash(testFilePath);

//            if (hashResult.Success)
//            {
//                verifyResult = _md5.VerifyFileHash(hashResult.HashString, testFilePath);

//                if (!verifyResult.Success)
//                {
//                    errorMessage = verifyResult.Message;
//                }
//            }
//            else
//            {
//                errorMessage = hashResult.Message;
//            }

//            Assert.IsTrue((hashResult.Success && verifyResult.Success), errorMessage);
//        }
//    }
//}
