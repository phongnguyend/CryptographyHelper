﻿namespace CryptographyHelper.AsymmetricAlgorithms
{
    public static class StringExtensions
    {
        public static RSA UseRSA(this string data, string keyXml)
        {
            return data.ToBytes().UseRSA(keyXml);
        }
    }
}