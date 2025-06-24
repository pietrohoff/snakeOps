#!/usr/bin/python3
import socket
import sys
import subprocess
import os

# Caminho da pasta com as wordlists
wordlist_dir = "wordlists/subdomains"

# Lista os arquivos disponíveis na pasta
print("\n📁 Wordlists disponíveis:")
arquivos = [f for f in os.listdir(wordlist_dir) if os.path.isfile(os.path.join(wordlist_dir, f))]
for i, arq in enumerate(arquivos, start=1):
    print(f"{i}. {arq}")

# Escolha da wordlist
escolha = input("\nDigite o número da wordlist desejada: ")
try:
    escolha_idx = int(escolha) - 1
    wordlist_path = os.path.join(wordlist_dir, arquivos[escolha_idx])
except (ValueError, IndexError):
    print("❌ Escolha inválida.")
    sys.exit(1)

# Lê os subdomínios
with open(wordlist_path, "r") as arquivo:
    subdominios = [linha.strip() for linha in arquivo if linha.strip()]

if len(sys.argv) < 2:
    print("Uso: python3 dnsRes.py <domínio>")
    sys.exit(1)

dominio = sys.argv[1]

# Resolve o domínio principal
try:
    ip_principal = socket.gethostbyname(dominio)
    print(f"\n🌐 Domínio principal: {dominio} --> {ip_principal}")
except socket.gaierror:
    print("Erro ao resolver DNS principal.")
    sys.exit(1)

# Buscar subdomínios e guardar IPs únicos
print("\n🔍 Procurando subdomínios comuns...\n" + "-"*40)
subdominios_encontrados = []
ips_unicos = {}

for sub in subdominios:
    subdominio = f"{sub}.{dominio}"
    try:
        ip = socket.gethostbyname(subdominio)
        if ip not in ips_unicos:
            ips_unicos[ip] = [subdominio]
        else:
            ips_unicos[ip].append(subdominio)
        print(f"{subdominio:<30} --> {ip}")
    except socket.gaierror:
        pass

# Scan no domínio principal
resposta = input(f"\nDeseja realizar um port scan em {dominio}? (s/n): ").lower()
if resposta == 's':
    banner_scan = input("Deseja capturar banners? (s/n): ").lower()
    banner_flag = "true" if banner_scan == "s" else "false"
    print(f"\n🚀 Iniciando port scan em {ip_principal}...\n" + "-"*40)
    subprocess.run(["python3", "portScan.py", ip_principal, banner_flag])

# Scan nos IPs únicos encontrados nos subdomínios
for ip, subdoms in ips_unicos.items():
    if ip == ip_principal:
        continue  # evita escanear duas vezes o IP do domínio principal
    nomes = ", ".join(subdoms[:2]) + ("..." if len(subdoms) > 2 else "")
    resposta = input(f"\nDeseja escanear {nomes} ({ip})? (s/n): ").lower()
    if resposta == 's':
        banner_scan = input("Capturar banners também? (s/n): ").lower()
        banner_flag = "true" if banner_scan == "s" else "false"
        print(f"\n🚀 Iniciando port scan em {ip}...\n" + "-"*40)
        subprocess.run(["python3", "portScan.py", ip, banner_flag])
