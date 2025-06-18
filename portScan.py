#!/usr/bin/python3
import socket
import sys

if len(sys.argv) < 2:
    print("Uso: python3 portScan.py <IP> [banner_scan true|false]")
    sys.exit(1)

ip_alvo = sys.argv[1]
banner_scan = sys.argv[2] if len(sys.argv) > 2 else "false"

for porta in range(1, 101):
    if banner_scan == "true":
        try:
            meus_sockets = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            meus_sockets.settimeout(1)
            resultado = meus_sockets.connect_ex((ip_alvo, porta))

            if resultado == 0:
                banner = ""
                try:
                    if porta == 80:
                        # Envia uma requisição HTTP para obter a resposta
                        meus_sockets.sendall(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % ip_alvo.encode())
                    # Tenta receber o banner (mesmo se não for HTTP)
                    resposta = meus_sockets.recv(1024).decode(errors="ignore").strip()
                    banner = resposta.split('\r\n')[0] if resposta else "Sem banner"
                except:
                    banner = "Sem banner"
                print(f"- Porta {porta} aberta | {banner}")

            meus_sockets.close()

        except Exception as e:
            print(f"[ERRO] Porta {porta}: {e}")
    else:

        try:
            meus_sockets = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            meus_sockets.settimeout(1)
            resultado = meus_sockets.connect_ex((ip_alvo, porta))

            if resultado == 0:
                print(f"- Porta {porta} aberta")
            meus_sockets.close()

        except Exception as e:
            print(f"[ERRO] Porta {porta}: {e}")
