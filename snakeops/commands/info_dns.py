"""infoDns — enumeração DNS usando utilitário 'host' (sem libs externas)

Mantém a ideia original do script do usuário: consultar múltiplos tipos de
registros via 'host', tentar AXFR, extrair IPs A/AAAA e consultar PTR.
Saída clara, por seções, e exibindo o *comando* executado.

Exemplos:
  python3 snakeOps infoDns exemplo.com
  python3 snakeOps infoDns -l
  python3 snakeOps infoDns -l -f data/lists/domains.txt
  python3 snakeOps infoDns exemplo.com -l -f data/lists/domains.txt

Observação: requer a ferramenta de sistema 'host' disponível no PATH.
"""
import argparse
import subprocess
import re
import ipaddress
import time
from pathlib import Path
from typing import List, Dict

COMMAND_NAME = "infoDns"
COMMAND_HELP = "Enumera DNS via 'host' (A/AAAA/MX/TXT/NS/... + AXFR + PTR), mostrando os comandos executados."

DEFAULT_TYPES = [
    "A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "SRV", "CAA", "HINFO",
    "NAPTR", "CERT", "DNSKEY", "DS", "LOC", "SPF", "SSHFP", "TLSA", "URI"
]

def print_rule():
    print("=" * 60)

def print_section(title: str):
    print()
    print_rule()
    print(f"🔍 {title}")
    print_rule()

def _run(cmd: List[str], timeout: int = 8, quiet_cmd: bool = False) -> List[str]:
    if not quiet_cmd:
        print(f"  $ {' '.join(cmd)}")
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout)
        lines = out.decode(errors="replace").strip().splitlines()
        if lines:
            for line in lines:
                print(f"    {line}")
        else:
            print("    (sem saída)")
        return lines
    except subprocess.CalledProcessError as e:
        print(f"    ❌ erro (exit {e.returncode})")
        if e.output:
            for line in e.output.decode(errors='replace').splitlines():
                print(f"    {line}")
        return []
    except subprocess.TimeoutExpired:
        print("    ⏱️ timeout")
        return []
    except FileNotFoundError:
        print("    ❌ 'host' não encontrado no PATH (instale dnsutils/bind9-dnsutils).")
        return []

def run_host_type(domain: str, record_type: str, timeout: int, quiet_cmd: bool):
    cmd = ["host", "-t", record_type, domain]
    return _run(cmd, timeout=timeout, quiet_cmd=quiet_cmd)

def enum_registros(domain: str, types: List[str], timeout: int, quiet_cmd: bool):
    for t in types:
        print_section(f"Registros {t}")
        lines = run_host_type(domain, t, timeout, quiet_cmd)
        if not lines:
            print("    ❌ Nenhum registro encontrado.")

def extrair_ips(domain: str, timeout: int, quiet_cmd: bool) -> List[str]:
    ips = []
    lines = []
    for t in ("A", "AAAA"):
        lines.extend(run_host_type(domain, t, timeout, quiet_cmd))
    for linha in lines:
        m4 = re.search(r"has address (\S+)", linha)
        m6 = re.search(r"has IPv6 address (\S+)", linha)
        if m4:
            ips.append(m4.group(1))
        elif m6:
            ips.append(m6.group(1))
    return ips

def tentativa_axfr(domain: str, timeout: int, quiet_cmd: bool):
    print_section("Transferência de Zona (AXFR)")
    # Obter NS
    ns_lines = run_host_type(domain, "NS", timeout, quiet_cmd)
    ns_list = []
    for linha in ns_lines:
        # tenta extrair servidores que terminam com ponto
        partes = linha.split()
        for parte in partes:
            if parte.endswith("."):
                ns_list.append(parte.strip("."))
    ns_list = list(dict.fromkeys(ns_list))  # unique mantendo ordem
    if not ns_list:
        print("    (nenhum NS identificado para tentativa de AXFR)")
        return

    for ns in ns_list:
        print(f"  \n\nTestando com {ns}...")
        cmd = ["host", "-l", domain, ns]
        lines = _run(cmd, timeout=timeout, quiet_cmd=quiet_cmd)
        if lines:
            print("  ⚠️  Transferência de zona POSSIVELMENTE PERMITIDA (verificar saída acima).")

def verificar_ptr(ip: str, timeout: int, quiet_cmd: bool):
    print_section(f"Resolução reversa (PTR) para IP {ip}")
    cmd = ["host", ip]
    _run(cmd, timeout=timeout, quiet_cmd=quiet_cmd)

def read_list_file(path: str) -> List[str]:
    p = Path(path)
    if p.exists():
        data = []
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            data.append(line)
        return data
    raise FileNotFoundError

def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="snakeOps infoDns",
        description="Enumeração DNS via utilitário 'host', com seções organizadas e comandos exibidos."
    )
    p.add_argument("domain", nargs="?", help="Domínio para analisar (ex: exemplo.com)")
    p.add_argument("-l", "--list", action="store_true", help="Ler domínios de uma lista (padrão: data/lists/domains.txt; fallback: dominios.txt)")
    p.add_argument("-f", "--file", default="data/lists/domains.txt", help="Caminho do arquivo de lista")
    p.add_argument("--no-axfr", action="store_true", help="Não tentar transferência de zona (AXFR)")
    p.add_argument("--types", nargs="+", default=DEFAULT_TYPES, help="Tipos de registro a consultar (padrão: conjunto amplo)")
    p.add_argument("--timeout", type=int, default=8, help="Timeout por comando (s) (padrão: 8)")
    p.add_argument("--sleep", type=float, default=1.0, help="Pausa entre domínios (s) para não 'floodar' (padrão: 1.0)")

    # >>> novo esquema de visibilidade do comando executado:
    p.add_argument("--show-cmd", dest="quiet_cmd", action="store_false",
                   help="Mostrar a linha de comando executada (por padrão NÃO mostra)")
    p.add_argument("--quiet-cmd", dest="quiet_cmd", action="store_true",
                   help="Ocultar a linha de comando executada (padrão)")
    p.set_defaults(quiet_cmd=True)
    return p

    p = argparse.ArgumentParser(
        prog="snakeOps infoDns",
        description="Enumeração DNS via utilitário 'host', com seções organizadas e comandos exibidos."
    )
    p.add_argument("domain", nargs="?", help="Domínio para analisar (ex: exemplo.com)")
    p.add_argument("-l", "--list", action="store_true", help="Ler domínios de uma lista (padrão: data/lists/domains.txt; fallback: dominios.txt)")
    p.add_argument("-f", "--file", default="data/lists/domains.txt", help="Caminho do arquivo de lista")
    p.add_argument("--no-axfr", action="store_true", help="Não tentar transferência de zona (AXFR)")
    p.add_argument("--types", nargs="+", default=DEFAULT_TYPES, help="Tipos de registro a consultar (padrão: conjunto amplo)")
    p.add_argument("--timeout", type=int, default=8, help="Timeout por comando (s) (padrão: 8)")
    p.add_argument("--sleep", type=float, default=1.0, help="Pausa entre domínios (s) para não 'floodar' (padrão: 1.0)")
    p.add_argument("--quiet-cmd", action="store_true", help="Não mostrar a linha de comando executada (por padrão MOSTRA)")
    return p

def analisar_dominio(domain: str, args):
    print(f"\n\n\n\n\n\n🌐 Iniciando análise do domínio: {domain}")
    enum_registros(domain, args.types, args.timeout, args.quiet_cmd)
    if not args.no_axfr:
        tentativa_axfr(domain, args.timeout, args.quiet_cmd)
    ips = extrair_ips(domain, args.timeout, args.quiet_cmd)
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
            verificar_ptr(ip, args.timeout, args.quiet_cmd)
        except ValueError:
            continue

def run(argv: List[str]):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    targets: List[str] = []
    if args.domain:
        targets.append(args.domain)

    if args.list:
        try:
            targets.extend(read_list_file(args.file))
        except FileNotFoundError:
            # fallback compatível com script antigo
            try:
                targets.extend(read_list_file("dominios.txt"))
            except FileNotFoundError:
                print(f"❌ Arquivo de lista não encontrado: {args.file} (nem 'dominios.txt').")

    # Se nada for passado, mostra ajuda específica do comando
    if not targets:
        parser.print_help()
        return

    # Normalizar e deduplicar simples
    seen = set()
    unique_targets = []
    for t in targets:
        d = t.strip().strip("/")
        if d and d not in seen:
            unique_targets.append(d)
            seen.add(d)

    for i, dominio in enumerate(unique_targets, 1):
        analisar_dominio(dominio, args)
        if i < len(unique_targets):
            time.sleep(max(0.0, args.sleep))
