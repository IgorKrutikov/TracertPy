import argparse
import re
import subprocess

import ipwhois


class TraceRouter:
    ip_v4_pattern = re.compile(r"([0-9]{1,3}\.){3}[0-9]{1,3}")
    SHELL_ENCODING = "cp1251"

    def __init__(self, domain_or_ip, steps=30):
        self.domain_or_ip = domain_or_ip
        self.steps_count = steps

    def exec(self):
        proc = subprocess.Popen(f"tracert -h {self.steps_count} -4 {self.domain_or_ip}",
                                shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        return proc.stdout

    def get_table_top(self):
        lines = []
        stdout = self.exec()
        stdout.readline()  # skip blank line
        st = self.get_ip(stdout.readline())
        while True:
            line = stdout.readline()
            if not line:
                break
            if ip := self.get_ip(line):
                lines.append(ip)
        return st, lines

    def get_ip(self, raw_line):
        string = raw_line.decode(self.SHELL_ENCODING)
        ip_v4 = self.ip_v4_pattern.search(string)

        if ip_v4:
            return ip_v4[0]
        else:
            return None


def get_ripe_data(target):
    try:
        data = ipwhois.IPWhois(target).lookup_whois()
        return {"country": data["asn_country_code"],
                "asn": f"AS{data['asn']}"
                }
    except ipwhois.IPDefinedError:
        return {"err": "address defined as Private-use"}


def main():
    line_pattern = "{:>3}) {:>17} {}"
    parser = argparse.ArgumentParser(
        description="""Пользователь вводит доменное имя или IP адрес.
                        Осуществляется трассировка до указанного узла, т. е.
                        мы узнаем IP адреса маршрутизаторов, через которые проходит пакет.
                        Необходимо определить к какой автономной системе относится каждый
                        из полученных IP адресов маршрутизаторов"""
    )

    parser.add_argument("target", type=str, help="Доменное имя или IP адрес")
    parser.add_argument("--hops", default=30, help="Количество прыжков (по умолчанию 30)")
    args = parser.parse_args()
    tracert = TraceRouter(args.target, args.hops)
    target_ip, path = tracert.get_table_top()
    print(f"Трассировка для адреса: {target_ip}")
    for i, line in enumerate(path):
        data = get_ripe_data(line)
        if not data.get("err"):
            print(line_pattern.format(i + 1, line, data["country"] + " " + data["asn"]))
        else:
            print(line_pattern.format(i + 1, line, data["err"]))


if __name__ == '__main__':
    main()
