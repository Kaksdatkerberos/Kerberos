using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;

namespace Kerberos
{
    class Program
    {
        static void Main(string[] args)
        {
            string ip = "127.0.0.1"; // локальный ip на котором будут сервера

            int portAS = 30000; // порт сервера AS
            int portTGS = 30001; // порт сервера TGS
            int portSS = 30002; // порт сервера SS

            string IV = "12346789"; // для шифрования AES (вектор IV)

            SimpleReadBehavior readBehavior = new SimpleReadBehavior();
            ASBehavior asBehavior = new ASBehavior("12345678", IV, "123", int.MaxValue);
            TGSBehavior tgsBehavior = new TGSBehavior("12345678", "12345679", int.MaxValue, IV);
            SSBehavior ssBehavior = new SSBehavior(IV);


            // инициализируем сервера
            Server AS = new Server(ip, portAS, "AS", asBehavior);
            Server TGS = new Server(ip, portTGS, "TGS", tgsBehavior);
            Server SS = new Server(ip, portSS, "SS", ssBehavior);


            // запускаем сервер каждый в отдельном потоке
            Thread threadAS = new Thread(AS.SatrtServing);
            threadAS.Start();
            Thread threadTGS = new Thread(TGS.SatrtServing);
            threadTGS.Start();
            Thread threadSS = new Thread(SS.SatrtServing);
            threadSS.Start();


            Client client = new Client("13");  // создаём клиента с id "13"

            byte[] as_ans = client.SendId(ip, portAS, out int numofbytes);  // отправляем id серверу AS, получаем от него зашифрованный нашим ключом

            string decoded_ans = client.DecodeAsAns(as_ans, IV, numofbytes);  // расшифровали ответ сервера с помощью нашего ключа

            string[] package1 = client.ExtractData(decoded_ans); // получили нужные нам поля в виде массива строк

            tgsBehavior.c_tgs_key = Helpers.StringToByteArray(package1[1]); // поскольку мы разделили реализации TGS и AS сервера у них нет общего пула данных
                                                                            // для простоты реализации решили сделать публичное поле и установить его значение из имеющихся данных

            byte[] tgs_ans = client.ToggleTGS(ip, portTGS, out numofbytes, package1, "SS", IV); // сделали запрос к TGS, получили ответ

            string decoded_tgs_ans = client.DecodeTGSAns(tgs_ans, IV, numofbytes, package1); // расшифровали ответ от TGS

            string[] package2 = client.ExtractData(decoded_tgs_ans); // получили нужные нам поля в виде массива строк

            ssBehavior.c_ss_key = Helpers.StringToByteArray(package2[1]);

            byte[] ss_ans = client.ToggleSS(ip, portSS, out numofbytes, package2, IV); // получили ответ от SS

            string decoded_ss_ans = client.DecodeSSAns(ss_ans, numofbytes, IV, Helpers.StringToByteArray(package2[1]));

            Console.WriteLine();
            Console.WriteLine("t4 + 1");
            Console.WriteLine(decoded_ss_ans);
            Console.WriteLine("----------");
            Console.WriteLine();

            Console.WriteLine("Протакол отработан");
        }
    }
}
