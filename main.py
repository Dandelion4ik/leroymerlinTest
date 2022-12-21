import socket
import json
import re
from contextlib import closing

pattern_leroy = re.compile(r"(leroymerlin[.]ru)")
pattern_lmru = re.compile(r"(lmru[.]tech)")

# САМЫЕ ПОПУЛЯРНЫЕ ПОРТЫ
ports = {21: "FTP", 22: "FTPS / SSH", 25: "SMTP", 80: "HTTPS", 110: "POP3", 143: 'IMAP', 443: 'HTTPS',
         587: 'SMTP SSL', 993: 'IMAP SSL', 995: 'POP3 SSL', 2082: 'cPanel', 2083: 'cPanel SSL',
         2086: 'WHM', 2087: 'WHM SSL', 2095: 'Webmail', 2096: 'Webmail SSL', 3306: 'MySQL'}

output = {}


def scan(url, domain):
    global output
    try:
        ip = socket.gethostbyname(url)
    except socket.error:
        return
    access_port = {'hostname': domain, 'ports': []}
    for port in ports:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                access_port['ports'].append({port: ports[port]})
            else:
                continue
    output[url] = [access_port]
    return


if __name__ == "__main__":
    file_name = 'list_of_hosts.txt'
    with open(file_name, mode="r") as file:
        for item in file:
            item = item.rstrip()
            if pattern_leroy.search(item):
                scan(item, 'leroymerlin.ru')
            elif pattern_lmru.search(item):
                scan(item, 'lmru.tech')
            else:
                continue
    with open('output.json', 'w', encoding='UTF-8') as file:
        json.dump(output, file)
