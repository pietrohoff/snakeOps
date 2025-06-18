#!/usr/bin/python3
import socket
import sys
import subprocess

# Lista básica de subdomínios
subdominios_comuns = [
    "www", "mail", "ftp", "webmail", "smtp", "imap", "api", "dev", "test", "vpn", "cpanel", "portal", "blog", "shop"
]

if len(sys.argv) < 2:
    print("Uso: python3 dnsRes.py <domínio>")
    sys.exit(1)

dominio = sys.argv[1]

# Resolve o domínio principal
try:
    ip_principal = socket.gethostbyname(dominio)
    print(f"\n{dominio} --> {ip_principal}")
except socket.gaierror:
    print("Erro ao resolver DNS principal.")
    sys.exit(1)

# Busca por subdomínios
print("\n🔍 Procurando subdomínios comuns...\n" + "-"*40)
subdominios_encontrados = []

for sub in subdominios_comuns:
    subdominio = f"{sub}.{dominio}"
    try:
        ip_sub = socket.gethostbyname(subdominio)
        print(f"{subdominio:<30} --> {ip_sub}")
        subdominios_encontrados.append((subdominio, ip_sub))
    except socket.gaierror:
        pass  # subdomínio não existe

# Oferece port scan no domínio principal
resposta = input(f"\nDeseja realizar um port scan em {dominio}? (s/n): ").lower()
if resposta == 's':
    banner_scan = input("Deseja capturar banners? (s/n): ").lower()
    banner_flag = "true" if banner_scan == "s" else "false"
    print(f"\nIniciando port scan em {ip_principal}...\n" + "-"*40)
    subprocess.run(["python3", "portScan.py", ip_principal, banner_flag])

# Oferece port scan em subdomínios encontrados
for subdominio, ip in subdominios_encontrados:
    resposta = input(f"\nDeseja escanear {subdominio} ({ip})? (s/n): ").lower()
    if resposta == 's':
        banner_scan = input("Capturar banners também? (s/n): ").lower()
        banner_flag = "true" if banner_scan == "s" else "false"
        print(f"\nIniciando port scan em {subdominio} ({ip})...\n" + "-"*40)
        subprocess.run(["python3", "portScan.py", ip, banner_flag])
