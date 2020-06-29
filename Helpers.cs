using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Kerberos
{
    class Helpers
    {
        // Будем использовать AES шифрование
        public static byte[] Encrypt(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;

            // Создаём объект для AES
            using (AesManaged aes = new AesManaged())
            {
                // Создаём шифровщика    
                ICryptoTransform encryptor = aes.CreateEncryptor(Key, IV);

                // Поток, в который будем писать  
                using (MemoryStream ms = new MemoryStream())
                {
                    // Создаём CryptoStream для непосредственного шифрования   
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        // Пишем в поток
                        using (StreamWriter sw = new StreamWriter(cs))
                            sw.Write(plainText);
                        encrypted = ms.ToArray();
                    }
                }
            }
            return encrypted;
        }

        // Расшифровка AES шифрования
        public static string Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string plaintext = null;
            // Создаём объект   
            using (AesManaged aes = new AesManaged())
            {
                // Создаём дешифровщик  
                ICryptoTransform decryptor = aes.CreateDecryptor(Key, IV);
                // Создаём поток куда пишем 
                using (MemoryStream ms = new MemoryStream(cipherText))
                {
                    // Создаём CryptoStream для дешифровки   
                    using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                    {
                        // Считываем результат дешифровки
                        using (StreamReader reader = new StreamReader(cs))
                            plaintext = reader.ReadToEnd();
                    }
                }
            }
            return plaintext;
        }

        // Вычисление SHA-256 хэша
        public static byte[] ComputeSha256Hash(string rawData)
        {
            using (SHA256 sha256Hash = SHA256.Create())
            {
                byte[] bytes = sha256Hash.ComputeHash(Encoding.Unicode.GetBytes(rawData));

                return bytes;
            }
        }

        // Перевод 16чной строки в массив байт
        public static byte[] StringToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}
