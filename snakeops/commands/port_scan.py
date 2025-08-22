import argparse
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple, Dict

COMMAND_NAME = "portScan"
COMMAND_HELP = "Scan TCP por perfil (leve/moderado/pesado/completo) e/ou lista/faixa, com banner opcional."

# Mapeamento de portas -> serviços (apenas informativo)
PORT_PROTOCOLS: Dict[int, str] = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 81: "HTTP-Alt", 88: "Kerberos",
    110: "POP3", 135: "RPC", 139: "NetBIOS-SSN", 143: "IMAP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    587: "Submission", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
    1025: "Ephemeral", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    2049: "NFS", 2375: "Docker", 2376: "Docker-TLS", 3000: "Dev-HTTP",
    3306: "MySQL", 3389: "RDP", 5432: "Postgres", 5601: "Kibana",
    5900: "VNC", 6379: "Redis", 8000: "HTTP-Alt", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 9000: "App-HTTP", 9200: "Elasticsearch",
    27017: "MongoDB",
}

# PERFIS
PROFILES: Dict[str, List[int]] = {
    # rápido: principais serviços de infra web/banco/desktop comuns
    "leve": sorted({
        20,21,22,23,25,53,80,81,88,110,135,139,143,389,443,445,465,587,636,993,995,
        1025,1433,1521,1723,2049,2375,2376,3000,3306,3389,5432,5601,5900,6379,8000,
        8080,8443,9000,9200,27017
    }),
    # igual ao comportamento padrão anterior
    "moderado": list(range(1, 101)),
    # well-known
    "pesado": list(range(1, 1025)),
    # tudo
    "completo": list(range(1, 65536)),
}

def _print_header(target: str, ports: List[int], banner: bool, preview: int, profile: str):
    preview = max(1, preview)
    head = ",".join(str(p) for p in ports[:preview])
    if len(ports) > preview:
        head += f",... (+{len(ports)-preview})"
    prof = f" (perfil: {profile})" if profile else ""
    print(f"\n🔍 Iniciando scan em {target}{prof}")
    print(f"   Banner: {'ativado' if banner else 'desativado'}\n")

def _parse_range(s: str) -> List[int]:
    a, b = s.split("-", 1)
    a, b = int(a), int(b)
    if a > b or a < 1 or b > 65535:
        raise ValueError("Faixa inválida. Use 1-65535 e a<=b.")
    return list(range(a, b + 1))

def _parse_ports(s: str) -> List[int]:
    out = []
    for item in s.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            out.extend(_parse_range(item))
        else:
            p = int(item)
            if p < 1 or p > 65535:
                raise ValueError("Porta fora de 1..65535.")
            out.append(p)
    # dedup preservando ordem
    seen = set()
    uniq = []
    for p in out:
        if p not in seen:
            seen.add(p)
            uniq.append(p)
    return uniq

def _parse_ports_file(path: str) -> List[int]:
    ports: List[int] = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # aceita "80", "1-1024" ou "22,80,443" em linhas diferentes
                if "," in line or "-" in line:
                    ports += _parse_ports(line)
                else:
                    p = int(line)
                    if 1 <= p <= 65535:
                        ports.append(p)
        # dedup mantendo ordem
        seen = set()
        uniq = []
        for p in ports:
            if p not in seen:
                seen.add(p)
                uniq.append(p)
        return uniq
    except FileNotFoundError:
        raise
    except Exception as e:
        raise ValueError(f"Erro ao ler arquivo de portas: {e}")

def _resolve_ipv4(target: str) -> str:
    try:
        socket.inet_aton(target)
        return target
    except OSError:
        return socket.gethostbyname(target)

def _try_banner(sock: socket.socket, port: int, host_header: str, timeout: float) -> str:
    banner = ""
    try:
        sock.settimeout(timeout)
        # passivo
        try:
            data = sock.recv(1024)
            if data:
                banner = data.decode(errors="ignore").strip()
        except Exception:
            banner = ""
        # ativo (HTTP) se nada veio
        if not banner and port in (80, 8080, 8000):
            try:
                req = (
                    f"GET / HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n"
                ).encode()
                sock.sendall(req)
                data = sock.recv(1024)
                banner = data.decode(errors="ignore").strip() if data else "Sem banner"
            except Exception:
                banner = "Sem banner"
        if not banner:
            banner = "Sem banner"
    except Exception:
        banner = "Sem banner"
    return banner.splitlines()[0] if banner else "Sem banner"

def _scan_one(ip: str, port: int, timeout: float, banner: bool, host_header: str) -> Tuple[int, bool, str, str]:
    service = PORT_PROTOCOLS.get(port, "Desconhecido")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        res = sock.connect_ex((ip, port))
        if res == 0:
            b = _try_banner(sock, port, host_header, timeout) if banner else ""
            try:
                sock.close()
            except Exception:
                pass
            return (port, True, service, b)
        else:
            try:
                sock.close()
            except Exception:
                pass
            return (port, False, service, "")
    except Exception:
        return (port, False, service, "")

def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="snakeOps portScan",
        description="Varredura TCP por perfil (leve/moderado/pesado/completo), e/ou lista/faixa. Zero-deps."
    )
    p.add_argument("target", help="IP ou hostname alvo")
    # Perfis prontos
    p.add_argument("--profile", choices=["leve", "moderado", "pesado", "completo"],
                   help="Escolhe um perfil de portas (leve/moderado/pesado/completo)")
    # Portas custom
    p.add_argument("--ports", help="Lista de portas/faixas (ex.: 22,80,443 ou 1-100,8080)")
    p.add_argument("--range", dest="range_", help="Faixa única (ex.: 1-100)")
    p.add_argument("--ports-file", help="Arquivo com portas (uma por linha, ou faixas/linhas com vírgulas)")
    # Comportamento
    p.add_argument("--banner", action="store_true", help="Tentar capturar banner (HTTP GET em 80/8080/8000)")
    p.add_argument("--show-closed", action="store_true", help="Exibir também portas fechadas (padrão: não)")
    p.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout por porta (s)")
    p.add_argument("-w", "--workers", type=int, default=100, help="Conexões simultâneas")
    p.add_argument("--preview", type=int, default=15, help="Quantas portas mostrar no cabeçalho (padrão: 15)")
    return p

def run(argv: List[str]):
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # 1) monta lista de portas a partir do perfil (se houver)
    ports: List[int] = []
    used_profile = None
    if args.profile:
        ports += PROFILES[args.profile]
        used_profile = args.profile

    # 2) soma portas vindas de --ports / --range / --ports-file (se passadas)
    if args.ports:
        ports += _parse_ports(args.ports)
    if args.range_:
        ports += _parse_range(args.range_)
    if args.ports_file:
        ports += _parse_ports_file(args.ports_file)

    # 3) se nada foi definido, mantém padrão "moderado" (1..100)
    if not ports:
        ports = PROFILES["moderado"]
        used_profile = "moderado"

    # dedup + ordena
    ports = sorted(set(ports))

    # resolve IP
    try:
        ip = _resolve_ipv4(args.target)
    except Exception as e:
        print(f"[ERRO] Falha ao resolver alvo '{args.target}': {e}")
        return

    _print_header(args.target, ports, args.banner, args.preview, used_profile or "")

    results = []
    with ThreadPoolExecutor(max_workers=max(1, min(args.workers, len(ports)))) as ex:
        futs = {ex.submit(_scan_one, ip, p, args.timeout, args.banner, args.target): p for p in ports}
        for f in as_completed(futs):
            try:
                results.append(f.result())
            except Exception:
                pass

    for port, is_open, service, banner in sorted(results, key=lambda x: x[0]):
        if is_open:
            if args.banner:
                print(f"- [✅ ABERTA] Porta {port} ({service}) | Banner: {banner}")
            else:
                print(f"- [✅ ABERTA] Porta {port} ({service})")
        elif args.show_closed:
            print(f"- [⛔ FECHADA] Porta {port}")
