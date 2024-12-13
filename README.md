# Http to socks5 proxy (HTTP/HTTPS Proxy через SOCKS5)

Этот проект представляет собой прокси-сервер, который перенаправляет HTTP и HTTPS запросы через SOCKS5 прокси. Программа поддерживает аутентификацию на SOCKS5 прокси и может работать как с HTTP, так и с HTTPS запросами.

## Помощь при отсутствии поддержки SOCKS5:
Если у вас есть программа, которая не поддерживает SOCKS5 прокси, этот прокси-сервер может помочь вам обойти это ограничение. Вы можете настроить вашу программу для использования HTTP или HTTPS прокси, указав адрес и порт, на котором работает этот прокси-сервер. Таким образом, ваша программа будет использовать этот прокси-сервер как посредника, который, в свою очередь, будет перенаправлять запросы через SOCKS5 прокси.

## Установка:

1. Убедитесь, что у вас установлен Python 3.x.
2. Установите необходимые зависимости:

```sh
pip install PySocks
```
3. Откройте файл proxy.py и заполните данные для подключения к вашему SOCKS5 прокси
``` python
s5_host = 'your_socks5_host'
s5_port = your_socks5_port
s5_username = 'your_socks5_username'
s5_password = 'your_socks5_password'
```
4. Запустите прокси-сервер:
``` sh
python proxy.py
```
P.S. По умолчанию прокси-сервер будет слушать на localhost:62225. Вы можете изменить порт, передав его в качестве аргумента функции main:
``` python 
main(s5_host, s5_port, s5_username, s5_password, proxy_port=your_desired_port)
```

## Ошибки:
Ошибки логируются в файл errors.log.
