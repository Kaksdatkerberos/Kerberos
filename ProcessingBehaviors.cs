using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Threading;

namespace Kerberos
{
    class SimpleReadBehavior : IProcessingBehavior
    {
        public byte[] ProcessData(byte[] data, int numberOfBytesRead)
        {
            string message = Encoding.Unicode.GetString(data, 0, numberOfBytesRead);
            Console.WriteLine("Server recived {0}", message);

            byte[] dummy = Encoding.Unicode.GetBytes("Finished");
            return dummy;
        }

    }

    // Поведение AS сервера (обработка данных от пользователя (id) и выдача TGT, K_C_TGS
    class ASBehavior : IProcessingBehavior
    {
        byte[] as_tgs_key;
        byte[] as_tgs_IV;
        string tgs_id;
        int p1;

        public ASBehavior(string as_tgs_key, string as_tgs_IV, string tgs_id, int p1)
        {
            this.as_tgs_key = Encoding.Unicode.GetBytes(as_tgs_key);
            this.as_tgs_IV = Encoding.Unicode.GetBytes(as_tgs_IV);
            this.tgs_id = tgs_id;
            this.p1 = p1;
        }

        public byte[] ProcessData(byte[] data, int numberOfBytesRead)
        {
            string id = Encoding.Unicode.GetString(data, 0, numberOfBytesRead);
            string k_c_tgs;

            byte[] temp = new byte[32];

            Random random = new Random();

            // Получаем случайный набор байт
            random.NextBytes(temp);

            // Создаём ключ Kc_TGS 
            k_c_tgs = BitConverter.ToString(temp);

            // Создаём TGT
            // Представляет собой строку, в которой храним наши данные {c, tgs, t1, p1, Kc_TGS}
            string TGT = string.Format("{0}\n\n\n\n{1}\n\n\n\n{2}\n\n\n\n{3}\n\n\n\n{4}", id, tgs_id, DateTime.Now.ToOADate(), p1, k_c_tgs);

            // Шифруем TGT с использованием Kas_TGS
            byte[] TGT_enc = Helpers.Encrypt(TGT, as_tgs_key, as_tgs_IV);

            // Приводим к строке
            string TGT_enc_s = Encoding.Unicode.GetString(TGT_enc);

            // Добавляем ключ Kc_TGS
            TGT_enc_s = TGT_enc_s + string.Format("\n\n\n\n{0}", k_c_tgs);

            // Получаем основной ключ клиента (SHA-256 хэш id)
            byte[] Kc = Helpers.ComputeSha256Hash(id);

            // Шифруем с его помощью наш пакет
            byte[] ans = Helpers.Encrypt(TGT_enc_s, Kc, as_tgs_IV);

            return ans; 
        }
    }

    class TGSBehavior : IProcessingBehavior
    {
        byte[] tgs_ss_key;
        public byte[] c_tgs_key;
        byte[] as_tgs_key;
        byte[] IV;
        int p2;

        public TGSBehavior(string as_tgs_key, string tgs_ss_key, int p2, string IV)
        {
            this.tgs_ss_key = Encoding.Unicode.GetBytes(tgs_ss_key);
            this.as_tgs_key = Encoding.Unicode.GetBytes(as_tgs_key);
            this.IV = Encoding.Unicode.GetBytes(IV);
            this.p2 = p2;
        }

        public byte[] ProcessData(byte[] data, int numberOfBytesRead)
        {
            string k_c_ss;

            byte[][] t = ParseData(data, numberOfBytesRead);

            string c = Helpers.Decrypt(t[0], c_tgs_key, IV);

            char[] sep = new char[] { '\n' };

            c = c.Split(sep)[0];

            byte[] temp = new byte[32];

            Random random = new Random();

            // Получаем случайный набор байт
            random.NextBytes(temp);

            // Создаём ключ Kc_SS
            k_c_ss = BitConverter.ToString(temp).Replace("-", string.Empty);

            // Сформировали TGS в открытом виде
            string TGS = string.Format("{0}\n\n\n\n{1}\n\n\n\n{2}\n\n\n\n{3}\n\n\n\n{4}", c, Encoding.Unicode.GetString(t[1]), DateTime.Now.ToOADate(), p2, k_c_ss);

            // Шифруем ключом K_TGS_SS
            byte[] TGS_enc = Helpers.Encrypt(TGS, tgs_ss_key, IV);

            // Приводим к строке
            string TGS_enc_s = Encoding.Unicode.GetString(TGS_enc);

            // Добавляем ключ K_C_SS
            TGS_enc_s = TGS_enc_s + string.Format("\n\n\n\n{0}", k_c_ss);

            // Шифруем и приводим к байтам
            byte[] ans = Helpers.Encrypt(TGS_enc_s, c_tgs_key, IV);

            return ans;
        }

        byte[][] ParseData(byte[] data, int numberOfBytesRead)
        {
            string temp = Encoding.Unicode.GetString(data, 0, numberOfBytesRead);

            string[] sep = new string[] { "\n\n\n\n" };

            string[] temp2 = temp.Split(sep, StringSplitOptions.RemoveEmptyEntries);  // temp2[0] - {TGT}K_AS_TGS
                                                                                      // temp2[1] - {Aut1}K_C_TGS
                                                                                      // temp2[2] - ID

            // Сохраняем нужную нам информацию в разных ячейках массива
            byte[][] t = new byte[3][];
            byte[] t1 = Encoding.Unicode.GetBytes(temp2[1]);
            byte[] t2 = Encoding.Unicode.GetBytes(temp2[2]);
            byte[] t3 = Encoding.Unicode.GetBytes(temp2[0]);

            t[0] = new byte[t1.Length];
            t[1] = new byte[t2.Length];
            t[2] = new byte[t3.Length];
            

            Array.Copy(t1, t[0], t1.Length);
            Array.Copy(t2, t[1], 4);
            Array.Copy(t3, t[2], t3.Length);

            return t;
        }
    }

    class SSBehavior : IProcessingBehavior
    {
        public byte[] c_ss_key;
        byte[] IV;

        public SSBehavior(string IV)
        {
            this.IV = Encoding.Unicode.GetBytes(IV);
        }

        public byte[] ProcessData(byte[] data, int numberOfBytesRead)
        {
            string[] s = ParseData(data, numberOfBytesRead); // получили данные

            string aut2 = Helpers.Decrypt(Encoding.Unicode.GetBytes(s[1]), c_ss_key, IV); // расшифровали

            string[] sep = new string[] { "\n\n\n\n" }; // разделитель

            double t4 = Convert.ToDouble(aut2.Split(sep, StringSplitOptions.RemoveEmptyEntries)[1]); // получили t4

            t4++; // t4 + 1

            string msg = string.Format("{0}", t4); // сформировали сообщение от SS

            byte[] ans = Helpers.Encrypt(msg, c_ss_key, IV);

            return ans;
        }

        // Парсим принятые данные
        public string[] ParseData(byte[] data, int numberOfBytesRead)
        {
            string temp = Encoding.Unicode.GetString(data, 0, numberOfBytesRead); // получили переданную строку

            string[] sep = new string[] { "\n\n\n\n" }; // обозначили разделитель

            string[] temp2 = temp.Split(sep, StringSplitOptions.RemoveEmptyEntries);  // temp2[0] - {TGS}K_TGS_SS
                                                                                      // temp2[1] - {Aut2}K_C_SS

            return temp2;
        }
    }
}
