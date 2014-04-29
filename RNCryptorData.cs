using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;

namespace RNCryptorDecrypt
{
    /// <summary>
    /// Represents encrypted data produced by the RNCryptor library. Format documented
    /// here: https://github.com/RNCryptor/RNCryptor-Spec/blob/master/RNCryptor-Spec-v2.md
    /// </summary>
    public class RNCryptorData
    {
        /// <summary>
        /// Total header length in bytes. Includes version, options, encryption salt, hmac salt and IV
        /// in that order.
        /// </summary>
        public const uint HEADER_LENGTH = 1 + 1 + 8 + 8 + 16;

        /// <summary>
        /// Total footer length in bytes. Includes hmac.
        /// </summary>
        public const uint FOOTER_LENGTH = 32;

        public byte Version { get; set; }
        public byte Options { get; set; }
        public IBuffer EncryptionSalt { get; set; }
        public IBuffer HMACSalt { get; set; }
        public IBuffer IV { get; set; }
        public IBuffer CipherText { get; set; }
        public IBuffer HMAC { get; set; }

        public IBuffer GetBufferWithoutHMAC()
        {
            bool usesPassword = (Options & (byte)1) == (byte)1;
            using(var ms = new MemoryStream((int)(HEADER_LENGTH + CipherText.Length)))
            using(var writer = new BinaryWriter(ms))
            {
                writer.Write(Version);
                writer.Write(Options);
                if (usesPassword)
                {
                    writer.Write(EncryptionSalt.ToByteArray());
                    writer.Write(HMACSalt.ToByteArray());
                }
                writer.Write(IV.ToByteArray());
                writer.Write(CipherText.ToByteArray());

                return ms.ToArray().ToBuffer();
            }
        }

        public byte[] GetBuffer()
        {
            bool usesPassword = (Options & (byte)1) == (byte)1;
            using (var ms = new MemoryStream((int)(HEADER_LENGTH + CipherText.Length)))
            using (var writer = new BinaryWriter(ms))
            {
                writer.Write(Version);
                writer.Write(Options);
                if (usesPassword)
                {
                    writer.Write(EncryptionSalt.ToByteArray());
                    writer.Write(HMACSalt.ToByteArray());
                }
                writer.Write(IV.ToByteArray());
                writer.Write(CipherText.ToByteArray());
                writer.Write(HMAC.ToByteArray());

                return ms.ToArray();
            }
        }

        public static RNCryptorData FromBase64String(string b64)
        {
            // decode from base64
            byte[] data = CryptographicBuffer.DecodeFromBase64String(b64).ToByteArray();

            // parse out the data
            using(var ms = new MemoryStream(data))
            using (var reader = new BinaryReader(ms))
            {
                var cryptorData = new RNCryptorData
                {
                    Version = reader.ReadByte(),
                    Options = reader.ReadByte()
                };

                bool usesPassword = (cryptorData.Options & (byte)1) == (byte)1;
                cryptorData.EncryptionSalt =  usesPassword ? reader.ReadBytes(8).ToBuffer() : null;
                cryptorData.HMACSalt = usesPassword ? reader.ReadBytes(8).ToBuffer() : null;
                cryptorData.IV = reader.ReadBytes(16).ToBuffer();
                cryptorData.CipherText = reader.ReadBytes((int)(data.Length - (HEADER_LENGTH + FOOTER_LENGTH))).ToBuffer();
                cryptorData.HMAC = reader.ReadBytes(32).ToBuffer();

                return cryptorData;
            }
        }
    }
}
