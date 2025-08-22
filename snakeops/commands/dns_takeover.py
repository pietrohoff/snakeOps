import argparse
import subprocess
import socket
import sys
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Tuple, Optional

COMMAND_NAME = "dnsTakeover"
COMMAND_HELP = "Verifica subdomínios (CNAME, A/AAAA) e possíveis takeovers via assinaturas conhecidas."

# Assinaturas padrão (mesmas do seu script, pode estender via --signatures-file)
TAKEOVER_SIGNATURES: Dict[str, str] = {
    "s3.amazonaws.com": "NoSuchBucket",
    "herokuapp.com": "No such app",
    "github.io": "There isn't a GitHub Pages site here",
    "readme.io": "Project doesnt exist",
    "surge.sh": "project not found",
    "statuspage.io": "This page is no longer available",
    "fastly.net": "Fastly error: unknown domain",
    "unbouncepages.com": "The requested URL was not found on this server",
    "bitbucket.io": "Repository not found",
}

# ------------------------- util -------------------------

def _rule():
    print("=" * 80)

def _run(cmd: List[str], timeout: int, show_cmd: bool = False) -> Tuple[int, str]:
    """Executa comando e retorna (exit_code, stdout)."""
    if show_cmd:
        print(f"  $ {' '.join(cmd)}")
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout)
        return 0, out.decode(errors="replace")
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output.decode(errors="replace") if e.output else ""
    except subprocess.TimeoutExpired:
        return 124, ""  # 124 = timeout style
    except FileNotFoundError:
        return 127, ""  # 127 = not found style

def _which(bin_name: str) -> bool:
    from shutil import which
    return which(bin_name) is not None

def _load_signatures_file(path: str) -> Dict[str, str]:
    sigs: Dict[str, str] = {}
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # formato: provider|assinatura
            if "|" in line:
                prov, sig = line.split("|", 1)
                prov = prov.strip()
                sig = sig.strip()
                if prov and sig:
                    sigs[prov] = sig
    return sigs

def _read_lines(path: str) -> List[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        return [ln.strip() for ln in fh if ln.strip() and not ln.strip().startswith("#")]

def _build_from_wordlist(domain: str, wordlist_path: str) -> List[str]:
    subs = _read_lines(wordlist_path)
    return [f"{s}.{domain}".strip(".") for s in subs]

def _extract_domain_from_sub(sub: str) -> Optional[str]:
    parts = sub.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return None

# ------------------------- parsing host -------------------------

def _parse_host_output(subdomain: str, output: str) -> Dict[str, List[str]]:
    """
    Retorna dict com chaves possiveis: alias (CNAME), ipv4, ipv6
    """
    result = {"alias": [], "ipv4": [], "ipv6": []}
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        # CNAME
        if " is an alias for " in line:
            # ex: foo.example.com is an alias for foo.s3.amazonaws.com.
            result["alias"].append(line)
        # IPv4
        if " has address " in line:
            # ex: foo.example.com has address 1.2.3.4
            ip = line.split()[-1]
            result["ipv4"].append(ip)
        # IPv6
        if " has IPv6 address " in line:
            ipv6 = line.split()[-1]
            result["ipv6"].append(ipv6)
    return result

def _alias_target_from_line(alias_line: str) -> Optional[str]:
    # pega tudo após "alias for"
    if "alias for" in alias_line:
        t = alias_line.split("alias for", 1)[-1].strip()
        return t.rstrip(".")
    return None

# ------------------------- takeover check -------------------------

def _maybe_check_takeover(subdomain: str, alias_target: str, signatures: Dict[str, str],
                          scheme: str, http_timeout: int, show_cmd: bool) -> Optional[str]:
    """
    Se o alias_target bater em algum provedor do dict de assinaturas,
    faz curl no subdomínio e procura a assinatura no conteúdo.
    Retorna uma string de alerta se detectar possível takeover.
    """
    alias_lower = alias_target.lower()
    matched_providers = [prov for prov in signatures if prov in alias_lower]
    if not matched_providers:
        return None  # alias não é de provedor com risco conhecido

    # Tenta http/https de acordo com scheme
    urls: List[str] = []
    if scheme == "http":
        urls = [f"http://{subdomain}"]
    elif scheme == "https":
        urls = [f"https://{subdomain}"]
    else:  # both
        urls = [f"http://{subdomain}", f"https://{subdomain}"]

    for prov in matched_providers:
        assinatura = signatures[prov].lower()
        for url in urls:
            code, body = _run(["curl", "-s", "-m", str(http_timeout), url], timeout=http_timeout+1, show_cmd=show_cmd)
            if code == 127:
                return "⚠️ 'curl' não encontrado no PATH (instale curl) — não foi possível validar takeover."
            if assinatura and (assinatura in (body or "").lower()):
                return f"⚠️ POSSÍVEL TAKEOVER → {prov} → assinatura '{assinatura}' detectada em {url}"
    return None

# ------------------------- worker -------------------------

def _check_one(subdomain: str, host_timeout: int, http_timeout: int, signatures: Dict[str, str],
               scheme: str, show_cmd: bool) -> List[str]:
    """
    Verifica um subdomínio, retorna linhas de resultado prontas para imprimir.
    """
    lines_out: List[str] = []
    code, host_out = _run(["host", subdomain], timeout=host_timeout, show_cmd=show_cmd)
    if code == 127:
        return ["    ❌ 'host' não encontrado no PATH (instale dnsutils/bind9-dnsutils)."]
    if code == 124:
        return [f"{subdomain:<40} ⏱️ timeout (DNS)"]

    if not host_out.strip():
        return []  # sem saída/sem resolução

    parsed = _parse_host_output(subdomain, host_out)

    # CNAMEs
    if parsed["alias"]:
        # mostra só a primeira linha de alias para não poluir
        alias_line = parsed["alias"][0]
        lines_out.append(f"{subdomain:<40} → 🧩 {alias_line}")
        alias_target = _alias_target_from_line(alias_line) or ""
        if alias_target:
            alert = _maybe_check_takeover(subdomain, alias_target, signatures, scheme, http_timeout, show_cmd)
            if alert:
                lines_out.append(f"{'':<40} {alert}")
            else:
                lines_out.append(f"{'':<40} ✅ CNAME válido")

    # IPv4 / IPv6
    if parsed["ipv4"]:
        for ip in parsed["ipv4"]:
            lines_out.append(f"{subdomain:<40} → ✅ {ip}")
    if parsed["ipv6"]:
        for ip6 in parsed["ipv6"]:
            lines_out.append(f"{subdomain:<40} → ✅ {ip6}")

    return lines_out

# ------------------------- CLI -------------------------

def build_arg_parser():
    p = argparse.ArgumentParser(
        prog="snakeOps dnsTakeover",
        description=(
            "Verifica subdomínios (CNAME, A/AAAA) e possíveis takeovers via assinaturas conhecidas. "
            "Entrada pode ser por dominio + wordlist de prefixos, ou lista de subdomínios."
        ),
    )
    # Modo 1: domínio + wordlist (prefixos)
    p.add_argument("--domain", help="Domínio base (ex.: exemplo.com) para construir subdomínios a partir de uma wordlist")
    p.add_argument("--wordlist", help="Arquivo com prefixos de subdomínio (um por linha), ex.: wordlists/subdomains/common.txt")

    # Modo 2: lista direta de subdomínios
    p.add_argument("--list", dest="listfile", help="Arquivo com subdomínios (um por linha). Se omitido, tenta 'lista.txt'")

    # Assinaturas extras
    p.add_argument("--signatures-file", help="Arquivo para extender as assinaturas (linhas 'provedor|assinatura')")

    # Execução/comportamento
    p.add_argument("-w", "--workers", type=int, default=50, help="Número de subdomínios em paralelo (padrão: 50)")
    p.add_argument("--host-timeout", type=int, default=6, help="Timeout (s) para chamadas 'host' (padrão: 6)")
    p.add_argument("--http-timeout", type=int, default=5, help="Timeout (s) para 'curl' (padrão: 5)")
    p.add_argument("--scheme", choices=["http", "https", "both"], default="http",
                   help="Esquema para validação do takeover (padrão: http)")
    p.add_argument("--show-cmd", action="store_true", help="Mostrar comandos 'host'/'curl' executados (padrão: não)")
    return p

def _resolve_base_domain_from_list(subdomains: List[str]) -> Optional[str]:
    # tenta extrair domínio base do primeiro sub
    for s in subdomains:
        d = _extract_domain_from_sub(s)
        if d:
            return d
    return None

def run(argv: List[str]):
    args = build_arg_parser().parse_args(argv)

    # Verificações de binários do sistema
    if not _which("host"):
        print("❌ 'host' não encontrado no PATH (instale dnsutils/bind9-dnsutils).")
        return
    if not _which("curl"):
        print("❌ 'curl' não encontrado no PATH (instale curl). (Ainda é possível listar CNAME/A/AAAA, mas sem validar takeover.)")

    # Carrega assinaturas
    signatures = dict(TAKEOVER_SIGNATURES)
    if args.signatures_file:
        try:
            signatures.update(_load_signatures_file(args.signatures_file))
        except Exception as e:
            print(f"⚠️ Não foi possível carregar --signatures-file: {e}")

    subdomains: List[str] = []
    domain_for_header: Optional[str] = None

    if args.listfile:
        try:
            subdomains = _read_lines(args.listfile)
        except FileNotFoundError:
            print(f"❌ Arquivo não encontrado: {args.listfile}")
            return
        domain_for_header = _resolve_base_domain_from_list(subdomains)

    elif args.domain:
        # precisa de wordlist para construir os subdomínios
        wl_path = args.wordlist
        if not wl_path:
            # tenta defaults convenientes
            # 1) wordlists/subdomains/ (primeiro arquivo .txt)
            # 2) data/lists/subdomains.txt
            # 3) erro
            base_dir = "wordlists/subdomains"
            chosen = None
            if os.path.isdir(base_dir):
                candidates = sorted([f for f in os.listdir(base_dir) if f.lower().endswith(".txt")])
                if candidates:
                    chosen = os.path.join(base_dir, candidates[0])
            if not chosen and os.path.exists("data/lists/subdomains.txt"):
                chosen = "data/lists/subdomains.txt"
            if not chosen and os.path.exists("wordlists/subdomains.txt"):
                chosen = "wordlists/subdomains.txt"
            if chosen:
                wl_path = chosen
                if args.show_cmd:
                    print(f"  (info) Usando wordlist padrão: {wl_path}")
            else:
                print("❌ Nenhuma wordlist informada e não encontrei defaults (wordlists/subdomains/*.txt ou data/lists/subdomains.txt).")
                return
        try:
            subdomains = _build_from_wordlist(args.domain, wl_path)
        except FileNotFoundError:
            print(f"❌ Wordlist não encontrada: {wl_path}")
            return
        domain_for_header = args.domain

    else:
        # fallback compatível: tenta 'lista.txt' na raiz
        if os.path.exists("lista.txt"):
            subdomains = _read_lines("lista.txt")
            domain_for_header = _resolve_base_domain_from_list(subdomains)
        else:
            print("Uso (modo 1): snakeOps dnsTakeover --domain exemplo.com --wordlist wordlists/subdomains/common.txt")
            print("Uso (modo 2): snakeOps dnsTakeover --list lista_subs.txt")
            print("Fallback: se nenhum parâmetro for passado, tenta carregar 'lista.txt' (se existir).")
            return

    if not subdomains:
        print("❌ Lista de subdomínios vazia.")
        return

    # Cabeçalho
    _rule()
    if domain_for_header:
        print(f"🌐 Domínio base: {domain_for_header} | Subdomínios carregados: {len(subdomains)}")
    else:
        print(f"🌐 Subdomínios carregados: {len(subdomains)}")
    print(f"   Esquema p/ takeover: {args.scheme} | Workers: {args.workers}")
    _rule()
    print("🔍 Verificando subdomínios ativos e possíveis takeovers...")
    _rule()

    # Execução paralela
    results: List[Tuple[int, List[str]]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {
            ex.submit(
                _check_one,
                s, args.host_timeout, args.http_timeout,
                signatures, args.scheme, args.show_cmd
            ): idx
            for idx, s in enumerate(subdomains)
        }
        for f in as_completed(futs):
            idx = futs[f]
            try:
                lines = f.result()
            except Exception as e:
                lines = [f"⚠️ erro inesperado no subdomínio idx {idx}: {e}"]
            results.append((idx, lines))

    # imprime preservando a ordem de entrada
    for _, lines in sorted(results, key=lambda x: x[0]):
        for ln in lines:
            print(ln)
