Высылаю презентации и пример реализации клиента и сервера. В архиве Solution Server, написанный в SharpDeveloper, в нем 2 проекта Client и Server.
Инструкция как запустить:
1. Открываете 2 консоли
2. В первой консоли запускаете исполняемый файл сервера (можете запустить из папки Debug или Release). Сборка проекта в Release или Debug настраивается в build -> Set configuration
3. Во второй консоли запускаете исполняемый файл клиента (тоже из Debug или Release) с параметром, в качестве параметра путь до текстового файла (Пример: client.exe c:\test.txt)
Клиент передает содержимое файла в бинарном виде серверу. Сервер печатает содержимое у себя в консоли и возвращает ответ клиенту. Клиент печатает ответ от сервера у себя в консоли.
В этом проекте есть все необходимые функции для реализации любой лабораторной работы.
Для реализации протокола Kerberos у вас будет два сервера (сервер Kerberos и сервера ресурсов), каждый на своем порту! Клиент в процессе работы протокола просто переключается с одного сервера на другой
