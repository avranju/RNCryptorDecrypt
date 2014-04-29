using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.Security.Cryptography;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=234238

namespace RNCryptorDecrypt
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page
    {
        public MainPage()
        {
            this.InitializeComponent();
            Init();
        }

        void Init()
        {
            var cipherText = "AgFr3Tvvq5F5cc2qFZmWXzM6ky4Dmz7wA3kDvMjYtwXO9rbR2weH8X+aDb5n5yU2sDbgxOuImm0jkCMUdC0+N6Z+K0T2a7XJnY68GSbmwH8lYQ==";
            var plainText = "ancd";
            var password = "c*0qlmVF";

            TestDecrypt(cipherText, password, plainText);
            var cipherText2 = TestEncrypt(plainText, password);
            TestDecrypt(cipherText2, password, plainText);
        }

        void TestDecrypt(string cipherText, string password, string expectedPlainText)
        {
            var cryptorData = RNCryptorData.FromBase64String(cipherText);
            var plainTextBuffer = RNCryptor.Decrypt(password, cryptorData);
            var plainText = CryptographicBuffer.ConvertBinaryToString(BinaryStringEncoding.Utf8,
                plainTextBuffer.ToBuffer());
            System.Diagnostics.Debug.Assert(plainText == expectedPlainText);
        }

        string TestEncrypt(string plainText, string password)
        {
            var cryptorData = RNCryptor.Encrypt(password,
                CryptographicBuffer.ConvertStringToBinary(
                    plainText,
                    BinaryStringEncoding.Utf8).ToByteArray());
            return CryptographicBuffer.EncodeToBase64String(cryptorData.GetBuffer().ToBuffer());
        }
    }
}
