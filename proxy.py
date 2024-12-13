import socket
import threading
import select
import socks
import re
import logging

# Login Data of your Socks5 proxy
s5_host = ''
s5_port = 1000
s5_username = ''
s5_password = ''

logging.basicConfig(
    level=logging.ERROR,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='errors.log',
    filemode='a',
    encoding='utf-8'
)

def extract_host(decoded_request: str) -> list[str] or None:
    """
        Извлекает хост и порт из декодированного HTTP-запроса.

        Аргументы:
            decoded_request (str): HTTP-запрос в виде декодированной строки.

        Возвращает:
            list[str] или None: Список, содержащий имя хоста в первом элементе
            и порт (если указан) во втором. Если порт не указан, второй элемент отсутствует.
            Возвращает None, если хост не найден.

        Примеры:
            # >>> extract_host("GET / HTTP/1.1\\r\\nHost: 112.14.21.13:8080\\r\\n\\r\\n")
            ['112.14.21.13', '8080']
            # >>> extract_host("GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n")
            ['example.com']
            # >>> extract_host("GET / HTTP/1.1\\r\\n\\r\\n")
            None
    """
    host = re.search(r"host: (\S+)", decoded_request, re.IGNORECASE)
    if not host:
        host = re.search(r'(?i)\bhttps?://([\w.-]+)', decoded_request)
        if host:
            return [host.group(1), host.group(2)] if host.group(2) else [host.group(1)]
        return None
    return host.group(1).split(":")


def parse_host(decoded_request: str) -> tuple[str, str, int] or None:
    """
        Анализирует HTTP-запрос и возвращает тип соединения, IP-адрес и порт.

        Аргументы:
            decoded_request (str): HTTP-запрос в виде декодированной строки.

        Возвращает:
            tuple[str, str, int]: Кортеж, содержащий тип соединения ('http' или 'https'),
            IPv4-адрес и порт. Возвращает None, если хост не найден или IP-адрес не может быть разрешён.

        Примеры:
            # >>> extract_host("GET / HTTP/1.1\\r\\nHost: 112.14.21.13:8080\\r\\n\\r\\n")
            ('http', '112.14.21.13', '8080')
            # >>> extract_host("GET / HTTP/1.1\\r\\n\\r\\n")
            None
    """
    host = extract_host(decoded_request)
    if not host:
        return None

    host_name = host[0]

    if len(host) > 1:
        port = int(host[1])
    else:
        port = 443 if "https" in decoded_request.lower() else 80

    host_type = "https" if port == 443 else "http"
    try:
        resolved_host = socket.getaddrinfo(host_name, port, socket.AF_INET)
        ipv4_address = resolved_host[0][4][0]
    except socket.gaierror:
        return None
    return host_type, ipv4_address, port


def https_connect_resolve(sk: socket.socket, ip_address: str, ip_port: int, socks5_host: str, socks5_port: int, socks5_username: str, socks5_password: str) -> None:
    """
        Устанавливает HTTPS-соединение с целевым сервером через SOCKS5-прокси и организует передачу данных между клиентом и сервером.

        Аргументы:
            sk (socket.socket): Сокет клиента для приема/передачи данных.
            ip_address (str): IP-адрес целевого сервера.
            ip_port (int): Порт целевого сервера.
            socks5_host (str): Адрес SOCKS5-прокси.
            socks5_port (int): Порт SOCKS5-прокси.
            socks5_username (str): Имя пользователя для аутентификации на SOCKS5-прокси.
            socks5_password (str): Пароль для аутентификации на SOCKS5-прокси.

        Возвращаемое значение:
            None: Функция завершает выполнение, закрывая соединение.

        Описание:
            Функция устанавливает соединение с указанным сервером через SOCKS5-прокси,
            передаёт HTTP-запросы серверу и возвращает ответ клиенту через заданный сокет.
    """
    try:
        proxy_socket = socks.socksocket()
        proxy_socket.set_proxy(socks.SOCKS5, socks5_host, socks5_port, True, socks5_username, socks5_password)
    except Exception as e:
        logging.error("Произошла ошибка: %s", str(e))
        return

    try:
        proxy_socket.connect((ip_address, ip_port))
        while True:
            ready_sockets, _, _ = select.select([sk, proxy_socket], [], [], 1)
            if not ready_sockets:
                continue
            for ready_sock in ready_sockets:
                data = ready_sock.recv(65536)
                if not data:
                    sk.close()
                    proxy_socket.close()
                    return
                if ready_sock is sk:
                    proxy_socket.sendall(data)
                else:
                    sk.sendall(data)
    except Exception as e:
        logging.error("Произошла ошибка: %s", str(e))
    finally:
        proxy_socket.close()
        sk.close()


def http_connect_resolve(sk: socket.socket, ip_address: str, ip_port: int, _request: bytes, socks5_host: str, socks5_port: int, socks5_username: str, socks5_password: str) -> None:
    """
        Создаёт http соединение с сервером через SOCKS5-прокси и пересылает данные.

        Аргументы:
            sk (socket.socket): Клиентский сокет для пересылки ответа.
            ip_address (str): IP-адрес сервера назначения.
            ip_port (int): Порт сервера назначения.
            _request (bytes): Данные HTTP-запроса.
            socks5_host (str): Хост SOCKS5-прокси.
            socks5_port (int): Порт SOCKS5-прокси.
            socks5_username (str): Логин для аутентификации на SOCKS5-прокси.
            socks5_password (str): Пароль для аутентификации на SOCKS5-прокси.

        Возвращаемое значение:
            None: Функция завершает выполнение, закрывая соединение.

        Описание:
            Функция устанавливает соединение с указанным сервером через SOCKS5-прокси,
            передаёт HTTP-запрос серверу и возвращает ответ клиенту через заданный сокет.
    """
    try:
        proxy_socket = socks.socksocket()
        proxy_socket.set_proxy(socks.SOCKS5, socks5_host, socks5_port, True, socks5_username, socks5_password)

        proxy_socket.connect((ip_address, ip_port))
        proxy_socket.sendall(_request)
    except Exception as e:
        logging.error("Произошла ошибка: %s", str(e))
        return

    try:
        response = b""
        proxy_socket.settimeout(3)
        try:
            while True:
                data = proxy_socket.recv(65536)
                if not data:
                    break
                response += data
        except socket.timeout:
            sk.sendall(response)
    except Exception as e:
        logging.error("Произошла ошибка: %s", str(e))
    finally:
        proxy_socket.close()
        sk.close()


def main(socks5_host, socks5_port, socks5_username, socks5_password, proxy_port=62225):
    http_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    http_socket.bind(('127.0.0.1', proxy_port))
    http_socket.listen(25)

    while True:
        sock, _ = http_socket.accept()
        sock.settimeout(0.3)

        request = b''
        try:
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                request += data
        except socket.timeout:
            pass
        decoded_request = request.decode(errors='ignore')

        try:
            ipv4_host_type, ipv4_address, ipv4_port = parse_host(decoded_request)
        except Exception as e:
            logging.error("Произошла ошибка: %s", str(e))
            continue

        if decoded_request.startswith("CONNECT"):
            sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            thread = threading.Thread(target=https_connect_resolve, args=(sock, ipv4_address, ipv4_port, socks5_host, socks5_port, socks5_username, socks5_password))
            thread.start()
        elif ipv4_host_type == "https":
            thread = threading.Thread(target=https_connect_resolve, args=(sock, ipv4_address, ipv4_port, socks5_host, socks5_port, socks5_username, socks5_password))
            thread.start()
        else:
            thread = threading.Thread(target=http_connect_resolve, args=(sock, ipv4_address, ipv4_port, request, socks5_host, socks5_port, socks5_username, socks5_password))
            thread.start()

if __name__ == "__main__":
    main(s5_host, s5_port, s5_username, s5_password)