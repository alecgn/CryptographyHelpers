﻿using System.Security.Authentication;

namespace CryptographyHelpers.Hash
{
    public class SHA1 : HashCore, ISHA1
    {
        private const HashAlgorithmType HashAlgorithm = HashAlgorithmType.Sha1;

        public SHA1() : base(HashAlgorithm) { }
    }
}