#!/usr/bin/python3
import os
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

# Define a faixa de IPs da rede local (exemplo: 192.168.0.1 a 192.168.0.254)
def get_local_subnet():
    ip = subprocess.getoutput("hostname -I").split()[0]
    base = ".".join(ip.split(".")[:3])
    return base

subnet = get_local_subnet()

print(f"🔍 Varredura na rede {subnet}.0/24...
{'-'*50}")

def scan_ip(ip):
    try:
        # Ping para ver se está ativo
        ping = subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL)
        if ping.returncode != 0:
            return

        # Coleta o hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = "desconhecido"

        # Coleta o MAC address com arp
        try:
            output = subprocess.check_output(["arp", "-n", ip]).decode()
            mac = output.split()[3] if "no entry" not in output else "desconhecido"
        except:
            mac = "erro"

        # Varredura de portas básicas
        portas_abertas = []
        for porta in [22, 23, 80, 443, 445, 3389, 3306, 8080]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            resultado = sock.connect_ex((ip, porta))
            if resultado == 0:
                portas_abertas.append(str(porta))
            sock.close()

        portas_str = ", ".join(portas_abertas) if portas_abertas else "nenhuma"

        print(f"IP: {ip} | MAC: {mac} | Hostname: {hostname} | Portas abertas: {portas_str}")

    except Exception as e:
        print(f"Erro com {ip}: {e}")

# Usa thread pool para paralelizar a varredura
with ThreadPoolExecutor(max_workers=50) as executor:
    for i in range(1, 255):
        ip = f"{subnet}.{i}"
        executor.submit(scan_ip, ip)
