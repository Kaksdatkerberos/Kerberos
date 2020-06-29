using System;
using System.Net;
using System.Net.Sockets;
using System.IO;
using System.Text;

namespace Kerberos
{
    class Server
    {
        IPAddress localAddr;
        int port;
        TcpListener Listener;
        string name;
        IProcessingBehavior processing;

        public Server(string ip, int port, string name, IProcessingBehavior processing)
        {
            this.port = port;
            localAddr = IPAddress.Parse(ip);
            Listener = new TcpListener(localAddr, port);
            this.name = name;
            this.processing = processing;
        }

        public void SatrtServing()
        {
            //Запускаем слушателя
            Listener.Start();

            //В бесконеном цикле принимаем новых клиентов
            while (true)
            {
                try
                {
                    //Ждем подключение клиента
                    using (TcpClient client = Listener.AcceptTcpClient())
                    {
                        Console.WriteLine("Client connected");
                        //Получаем сетевой поток от клиента
                        using (NetworkStream stream = client.GetStream())
                        {
                            byte[] buffer = new byte[1024];
                            byte[] result;
                            //Считываем данные 
                            int numberOfBytesRead = stream.Read(buffer, 0, buffer.Length);
                            if (numberOfBytesRead > 0)
                            {
                                // обрабатываем сообщение, возвращаем рузультат обрабортки
                                result = processing.ProcessData(buffer, numberOfBytesRead);
                            }
                            else
                            {
                                result = new byte[1];
                            }

                            //Отправляем ответ клиенту
                            stream.Write(result, 0, result.Length);
                        }
                    }
                }
                catch (SocketException e)
                {
                    Console.WriteLine("Server {0} stop", name);
                    Listener.Stop();
                    Console.WriteLine("SocketException: {0}", e);
                    break;
                }
            }
        }
    }
}
