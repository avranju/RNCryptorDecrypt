using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage.Streams;

namespace RNCryptorDecrypt
{
    /// <summary>
    /// This class provides an implementation of the cyrptographic algorithms as documented
    /// in the RNCryptor spec here: https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v2.md
    /// </summary>
    public class RNCryptor
    {
        public static byte[] Decrypt(string password, RNCryptorData cryptorData)
        {
            // derive key from password and encryption salt and decrypt data
            var encryptionKey = GeneratePBKDF2(
                password,
                cryptorData.EncryptionSalt,
                32, 10000);
            var plainText = AESDecrypt(cryptorData.CipherText, cryptorData.IV, encryptionKey);

            // verify that the hmac is valid
            if (!VerifyHMAC(password, cryptorData))
            {
                throw new InvalidOperationException("HMAC verification failed.");
            }

            return plainText.ToByteArray();
        }

        public static RNCryptorData Encrypt(string password, byte[] plainText)
        {
            var encryptionSalt = CryptographicBuffer.GenerateRandom(8);
            var encryptionKey = GeneratePBKDF2(password, encryptionSalt, 32, 10000);
            var hmacSalt = CryptographicBuffer.GenerateRandom(8);
            var hmacKey = GeneratePBKDF2(password, hmacSalt, 32, 10000);
            var iv = CryptographicBuffer.GenerateRandom(16);
            var cipherText = AESEncrypt(plainText.ToBuffer(), iv, encryptionKey);

            var cryptoData = new RNCryptorData
            {
                Version = 2,
                Options = 1,
                EncryptionSalt = encryptionSalt,
                HMACSalt = hmacSalt,
                IV = iv,
                CipherText = cipherText,
                HMAC = null
            };

            cryptoData.HMAC = ComputeHMAC(cryptoData.GetBufferWithoutHMAC(), hmacKey);
            return cryptoData;
        }

        private static bool VerifyHMAC(string password, RNCryptorData cryptorData)
        {
            // derive hmac key from password and hmac salt and compute hmac on the
            // header data from cryptorData and verify with hmac in cryptorData
            var hmacKey = GeneratePBKDF2(
                password,
                cryptorData.HMACSalt,
                32, 10000);

            return VerifyHMAC(cryptorData.GetBufferWithoutHMAC(), hmacKey, cryptorData.HMAC);
        }

        private static bool VerifyHMAC(IBuffer data, IBuffer hmacKeyBuffer, IBuffer hmac)
        {
            var provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha256);
            var key = provider.CreateKey(hmacKeyBuffer);
            return CryptographicEngine.VerifySignature(key, data, hmac);
        }

        private static IBuffer ComputeHMAC(IBuffer data, IBuffer hmacKeyBuffer)
        {
            var provider = MacAlgorithmProvider.OpenAlgorithm(MacAlgorithmNames.HmacSha256);
            var key = provider.CreateKey(hmacKeyBuffer);
            return CryptographicEngine.Sign(key, data);
        }

        private static IBuffer AESDecrypt(IBuffer cipherText, IBuffer IV, IBuffer keyBuffer)
        {
            var provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            var key = provider.CreateSymmetricKey(keyBuffer);
            return CryptographicEngine.Decrypt(key, cipherText, IV);
        }

        private static IBuffer AESEncrypt(IBuffer plainText, IBuffer IV, IBuffer keyBuffer)
        {
            var provider = SymmetricKeyAlgorithmProvider.OpenAlgorithm(SymmetricAlgorithmNames.AesCbcPkcs7);
            var key = provider.CreateSymmetricKey(keyBuffer);
            return CryptographicEngine.Encrypt(key, plainText, IV);
        }

        private static IBuffer GeneratePBKDF2(
            string password,
            IBuffer salt,
            UInt32 targetSize,
            UInt32 iterationCount)
        {
            var keyParams = KeyDerivationParameters.BuildForPbkdf2(salt, iterationCount);
            var provider = KeyDerivationAlgorithmProvider.OpenAlgorithm(KeyDerivationAlgorithmNames.Pbkdf2Sha1);
            var passwordBuffer = CryptographicBuffer.ConvertStringToBinary(password, BinaryStringEncoding.Utf8);
            var key = provider.CreateKey(passwordBuffer);
            return CryptographicEngine.DeriveKeyMaterial(key, keyParams, targetSize);
        }
    }
}
