using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Text;
using System.Security.Cryptography;

namespace Kerberos
{
    class Client
    {
        string id;

        public Client(string id)
        {
            this.id = id;
        }

        private byte[] Exchange(string address, int port, byte[] data, out int numberOfBytesRead)
        {
            byte[] buffer = new byte[1024];
            numberOfBytesRead = 0;
            try
            {
                //Инициализация клиента
                using (TcpClient client = new TcpClient(address, port))
                {
                    using (NetworkStream stream = client.GetStream())
                    {
                        //Отправляем данные
                        stream.Write(data, 0, data.Length);
                        //Считываем данные 
                        numberOfBytesRead = stream.Read(buffer, 0, buffer.Length);
                    }
                }
            }
            catch (SocketException e)
            {
                Console.WriteLine("SocketException: {0}", e);
            }
            return buffer;
        }

        // Отправляет ID AS (1 шаг)
        public byte[] SendId(string address, int port, out int numofbytes)
        {
            byte[] data = Encoding.Unicode.GetBytes(id); // подготовили ID к отправке
            byte[] ans = Exchange(address, port, data, out numofbytes);  // получили ответ сервера

            if (numofbytes == 0)
            {
                Console.WriteLine("Not data");
            }

            byte[] answer = new byte[numofbytes];
            Array.Copy(ans, answer, numofbytes);

            return answer;
        }

        // Расшифровываем то, что пришло от AS
        public string DecodeAsAns(byte[] ans, string IV, int numofbytes)
        {
            byte[] temp = new byte[numofbytes];
            Array.Copy(ans, temp, numofbytes);

            return Helpers.Decrypt(temp, Helpers.ComputeSha256Hash(id), Encoding.Unicode.GetBytes(IV));
        }

        // Получает поля из расшифрованных данных
        public string[] ExtractData(string decoded_ans)
        {
            string[] sep = new string[] { "\n\n\n\n" }; // объявляем разделитель

            string[] data = decoded_ans.Split(sep, StringSplitOptions.RemoveEmptyEntries);  // делим наше декодированное сообщение по разделителю
                                                                                            // data[0] - TGT или TGS
                                                                                            // data[1] - K_C_TGS или K_C_SS
            data[1] = data[1].Replace("-", string.Empty);
            return data;
        }

        // Делает запрос к TGS (2 шаг)
        public byte[] ToggleTGS(string address, int port, out int numofbytes, string[] key_and_tgt, string ss_id, string IV)
        {
            string aut1 = string.Format("{0}\n\n\n\n{1}", id, DateTime.Now.ToOADate()); // сформировали Aut1

            byte[] aut1_enc = Helpers.Encrypt(aut1, Helpers.StringToByteArray(key_and_tgt[1]), Encoding.Unicode.GetBytes(IV)); // зашифровали с помощью K_C_TGS

            string aut1_enc_s = Encoding.Unicode.GetString(aut1_enc); // привели к строке

            string message = string.Format("{0}\n\n\n\n{1}\n\n\n\n{2}", key_and_tgt[0], aut1_enc_s, ss_id); // сформировали сообщение для отправки

            byte[] data = Encoding.Unicode.GetBytes(message); // привели к массиву байт
            byte[] ans = Exchange(address, port, data, out numofbytes);

            if (numofbytes == 0)
            {
                Console.WriteLine("Not data");
            }

            byte[] answer = new byte[numofbytes];
            Array.Copy(ans, answer, numofbytes);

            return answer;
        }

        // Расшифровываем то, что пришло от TGS
        public string DecodeTGSAns(byte[] ans, string IV, int numofbytes, string[] key_and_tgt)
        {
            byte[] temp = new byte[numofbytes];
            Array.Copy(ans, temp, numofbytes);

            return Helpers.Decrypt(temp, Helpers.StringToByteArray(key_and_tgt[1]), Encoding.Unicode.GetBytes(IV));
        }

        // Делаем запрос к SS
        public byte[] ToggleSS(string address, int port, out int numofbytes, string[] key_and_tgs, string IV)
        {
            var t4 = DateTime.Now.ToOADate();
            string aut2 = string.Format("{0}\n\n\n\n{1}", id, t4); // сформировали Aut1

            Console.WriteLine();
            Console.WriteLine("t4");
            Console.WriteLine(t4);
            Console.WriteLine("----------");
            Console.WriteLine();

            byte[] aut2_enc = Helpers.Encrypt(aut2, Helpers.StringToByteArray(key_and_tgs[1]), Encoding.Unicode.GetBytes(IV)); // зашифровали с помощью K_C_SS

            string aut2_enc_s = Encoding.Unicode.GetString(aut2_enc); // привели к строке

            string message = string.Format("{0}\n\n\n\n{1}", key_and_tgs[0], aut2_enc_s); // сформировали сообщение для отправки

            byte[] data = Encoding.Unicode.GetBytes(message); // привели к массиву байт
            byte[] ans = Exchange(address, port, data, out numofbytes);

            if (numofbytes == 0)
            {
                Console.WriteLine("Not data");
            }

            byte[] answer = new byte[numofbytes];
            Array.Copy(ans, answer, numofbytes);

            return answer;
        }

        // Расшифровываем ответ от SS
        public string DecodeSSAns(byte[] ans, int numofbytes,string IV, byte[] key)
        {
            byte[] temp = new byte[numofbytes];
            Array.Copy(ans, temp, numofbytes);

            return Helpers.Decrypt(temp, key, Encoding.Unicode.GetBytes(IV));
        }
    }

}
