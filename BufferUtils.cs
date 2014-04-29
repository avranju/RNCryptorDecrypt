using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.Security.Cryptography;
using Windows.Storage.Streams;

namespace RNCryptorDecrypt
{
    public static class BufferUtils
    {
        /// <summary>
        /// Helper extension method to convert <see cref="IBuffer"/> objects to byte arrays.
        /// </summary>
        /// <param name="buffer">The <see cref="IBuffer"/> which needs to be converted to a <see cref="byte[]"/>.</param>
        /// <returns>A <see cref="byte[]"/> containing the data stored in <paramref name="buffer"/>.</returns>
        public static byte[] ToByteArray(this IBuffer buffer)
        {
            byte[] data;
            CryptographicBuffer.CopyToByteArray(buffer, out data);
            return data;
        }

        /// <summary>
        /// Helper extension method to convert a <see cref="byte[]"/> to an <see cref="IBuffer"/>.
        /// </summary>
        /// <param name="buffer">The <see cref="byte[]"/> that needs to be converted to an <see cref="IBuffer"/>.</param>
        /// <returns>An <see cref="IBuffer"/> instance containing the data stored in <paramref name="buffer"/>.</returns>
        public static IBuffer ToBuffer(this byte[] buffer)
        {
            return CryptographicBuffer.CreateFromByteArray(buffer);
        }
    }
}
