using CryptographyHelpers.Hash;
using FluentAssertions;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace CryptographyHelpers.Tests.Hash
{
    [TestClass]
    public class MD5Tests
    {
        private readonly MD5 _md5 = new();
        private readonly string _testString = "This is a test string!";
        private const string _md5HashTestString = "ACB5A0BB8B17EADA5ACD8CED350BB856";

        [TestMethod]
        public void ShouldComputeAndVerifyStringHash_InComputeHash()
        {
            var hashResult = _md5.ComputeHash(_testString);

            hashResult.Success.Should().BeTrue();
            hashResult.HashString.Should().Be(_md5HashTestString);
        }

        //[TestMethod]
        //public void ComputeAndVerifyHash_File()
        //{
        //    var testFilePath = Path.GetTempFileName();
        //    var verifyResult = new GenericHashResult();
        //    var errorMessage = "";

        //    File.WriteAllText(testFilePath, _testString);

        //    var hashResult = _md5.ComputeFileHash(testFilePath);

        //    if (hashResult.Success)
        //    {
        //        verifyResult = _md5.VerifyFileHash(hashResult.HashString, testFilePath);

        //        if (!verifyResult.Success)
        //        {
        //            errorMessage = verifyResult.Message;
        //        }
        //    }
        //    else
        //    {
        //        errorMessage = hashResult.Message;
        //    }

        //    Assert.IsTrue((hashResult.Success && verifyResult.Success), errorMessage);
        //}
    }
}
