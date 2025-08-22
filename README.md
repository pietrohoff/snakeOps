
# snakeOps

**Objetivo:** oferecer ferramentas de _recon_ e diagnóstico de rede em um **padrão único**, fáceis de usar, **sem dependências Python** (somente `python3` + utilitários do sistema como `host`/`curl`).

> ✅ Você roda tudo com `python3 snakeOps <comando> [opções]`  
> ✅ Funciona com **alvo único** ou **listas**  
> ✅ **Zero pip / venv** (só biblioteca padrão)  
> ✅ Saídas legíveis e previsíveis

---

## Índice

1. [Instalação & Estrutura](#instalação--estrutura)
2. [Como rodar (visão geral)](#como-rodar-visão-geral)
3. [Comandos](#comandos)
   - [infoDns](#infodns) — enumeração DNS via `host`
   - [portScan](#portscan) — varredura TCP (perfis leve/moderado/pesado/completo)
   - [dnsTakeover](#dnstakeover) — detecção de **possível** subdomain takeover
4. [Listas e Wordlists](#listas-e-wordlists)
5. [“Barulho” / Logs no alvo (OPSEC)](#barulho--logs-no-alvo-opsec)
6. [Exemplos rápidos (cola-e-roda)](#exemplos-rápidos-cola-e-roda)
7. [Dicas, troubleshooting & FAQ](#dicas-troubleshooting--faq)
8. [Adicionar novos comandos](#adicionar-novos-comandos)
9. [Avisos legais](#avisos-legais)

---

## Instalação & Estrutura

### Requisitos
- **Python 3** instalado.
- Utilitários do sistema (para alguns comandos):
  - `host` (pacote **dnsutils** / **bind9-dnsutils**) — usado em `infoDns` e `dnsTakeover`.
  - `curl` — usado em `dnsTakeover` para validar possíveis takeovers.
- **Sem** dependências Python externas.

### Estrutura sugerida do repositório

```
snakeOps/                      # raiz do projeto
├─ snakeOps                    # executável principal (rode com: python3 snakeOps)
├─ snakeops/
│  ├─ cli.py                   # roteador/descobridor de comandos
│  ├─ commands/
│  │  ├─ info_dns.py           # comando: infoDns
│  │  ├─ port_scan.py          # comando: portScan
│  │  └─ dns_takeover.py       # comando: dnsTakeover
│  └─ util/                    # utilitários compartilhados (se necessário)
├─ data/
│  └─ lists/
│     ├─ domains.txt           # lista de domínios (exemplo)
│     └─ subdomains.txt        # wordlist de subdomínios (opcional)
├─ wordlists/                  # suas wordlists pessoais (opcional)
│  └─ subdomains/
│     └─ ... .txt
└─ README.md                   # este guia
```

> Dê permissão de execução ao launcher (opcional):  
> `chmod +x snakeOps`

---

## Como rodar (visão geral)

Ajuda geral:
```bash
python3 snakeOps
# ou
python3 snakeOps -h
```

Ajuda de um comando específico:
```bash
python3 snakeOps <comando> -h
```

Padrão de execução (sempre igual):
```bash
python3 snakeOps <comando> [alvos/opções]
```

---

## Comandos

### infoDns

**O que é:** Enumeração DNS usando o binário `host`. Mostra **CNAME**, **A**, **AAAA**, tenta **AXFR** (transferência de zona) e faz **PTR** para IPs encontrados.

**Quando usar:**
- Recon inicial de domínios.
- Conferir se há **CNAMEs “órfãos”** ou apontando para provedores externos.
- Higiene de DNS após migrações.

**Sintaxe:**
```bash
python3 snakeOps infoDns <dominio>
python3 snakeOps infoDns -l [-f caminho/da/lista.txt]
```

**Opções principais:**
- `domain` (posicional): domínio único (ex.: `exemplo.com`).
- `-l, --list`: ler **lista** de domínios.
- `-f, --file`: arquivo de lista (padrão: `data/lists/domains.txt`). Se não existir, tenta `dominios.txt` na raiz.
- `--no-axfr`: não tentar transferência de zona.
- `--types A AAAA MX TXT ...`: limita tipos consultados (padrão: conjunto amplo).
- `--timeout 8`: timeout (s) por chamada ao `host` (padrão 8).
- `--sleep 1.0`: pausa (s) entre domínios (quando usa lista).
- `--show-cmd`: **mostra** o comando executado (`$ host ...`). Por padrão **não** mostra.

**Exemplos:**
```bash
# domínio único
python3 snakeOps infoDns exemplo.com

# lista padrão (data/lists/domains.txt)
python3 snakeOps infoDns -l

# lista custom
python3 snakeOps infoDns -l -f meus_dominios.txt

# limitar os tipos e pular AXFR
python3 snakeOps infoDns exemplo.com --types A AAAA MX TXT NS --no-axfr

# ver o comando 'host' usado
python3 snakeOps infoDns exemplo.com --show-cmd
```

**Saída (resumo):**
- Seções por tipo (A/AAAA/MX/TXT/NS...)
- Bloco “Transferência de Zona (AXFR)” por NS detectado.
- Blocos de **PTR** para cada IP resolvido.

**Barulho / Logs:**
- **Gera consultas DNS** (o seu **resolver**/DNS corporativo verá as requisições; os **autoritativos** podem ver AXFR).
- **AXFR** consulta diretamente os **nameservers autoritativos** — provavelmente **gera log** no provedor de DNS.
- Sem tráfego HTTP por padrão (exceto se você próprio abrir URLs).

---

### portScan

**O que é:** Varredura de **portas TCP** com perfis prontos e captura de **banner** opcional.

**Quando usar:**
- Recon de superfície de ataque.
- Checar exposição de serviços comuns (SSH, HTTP, RDP, DBs…).
- Validação rápida antes de uma análise mais profunda.

**Perfis:**
- `leve`: portas mais comuns (web, mail, DBs, desktop remotos etc.). **Rápido.**
- `moderado`: **1–100** (padrão).
- `pesado`: **1–1024** (well-known).
- `completo`: **1–65535** (demorado).

**Sintaxe:**
```bash
python3 snakeOps portScan <alvo> [opções]
```

**Opções principais:**
- `--profile {leve,moderado,pesado,completo}`: escolhe um perfil de portas.
- `--ports "22,80,443,8080"`: soma portas específicas (aceita faixas `1-100` e mistura).
- `--range 1-1024`: soma uma faixa única.
- `--ports-file arquivo.txt`: soma portas a partir de arquivo (uma por linha; aceita faixas/linhas com vírgula).
- `--banner`: tenta banner (primeiro passivo; se 80/8080/8000, envia um GET HTTP).
- `--show-closed`: também imprime portas fechadas.
- `-t, --timeout 1.0`: timeout por porta (s).
- `-w, --workers 100`: conexões simultâneas.
- `--preview 15`: quantas portas mostrar no cabeçalho (“1,2,3,... +N”).

**Exemplos:**
```bash
# rápido (comum) + banner
python3 snakeOps portScan 37.59.174.225 --profile leve --banner

# padrão (1..100)
python3 snakeOps portScan alvo.com

# well-known
python3 snakeOps portScan alvo.com --profile pesado

# tudo (demorado!)
python3 snakeOps portScan alvo.com --profile completo

# combinar perfis com lista/faixa
python3 snakeOps portScan alvo.com --profile leve --ports 8443,9200 --range 5000-5010 --banner

# a partir de arquivo
python3 snakeOps portScan alvo.com --ports-file minhas_portas.txt --banner --show-closed
```

**Saída (resumo):**
```
🔍 Iniciando scan em 10.0.0.5 (perfil: leve) nas portas: 22,80,443,8080,... (+N)
   Banner: ativado

[ABERTA] Porta 22 (SSH) | Banner: SSH-2.0-OpenSSH_9.6
[ABERTA] Porta 80 (HTTP) | Banner: HTTP/1.1 200 OK
...
```

**Barulho / Logs:**
- **Sim** — cada porta aberta tentará conexão TCP; **firewalls/IDS/servidores** podem logar/alertar.
- Com `--banner`, pode enviar um **HTTP GET** (80/8080/8000), o que **aparece nos logs** do web server.
- Ajuste `--workers` e `--timeout` para ser mais “gentil” se não quiser um pico de conexões.

---

### dnsTakeover

**O que é:** Verifica subdomínios em busca de indícios de **subdomain takeover** (ex.: CNAME para S3/Heroku/GitHub Pages sem recurso existente).  
Usa `host` para descobrir **CNAME/A/AAAA** e `curl` para procurar **assinaturas** de erro no conteúdo.

> **Atenção:** É uma heurística — pode haver falsos positivos/negativos. Confirme manualmente antes de qualquer ação.

**Quando usar:**
- Auditoria/bounty.
- Higiene de DNS após apagar buckets/apps/sites.
- Antes de publicar novos subdomínios, para checar resíduos.

**Modos de entrada:**
1) **Domínio + wordlist** de prefixos (gera `sub.dominio`):  
   `--domain exemplo.com --wordlist wordlists/subdomains/common.txt`  
   (se `--wordlist` não for informado, tenta alguns caminhos padrão)
2) **Lista pronta de subdomínios**:  
   `--list subs.txt` (um por linha). Se nada for informado, tenta `lista.txt` na raiz.

**Sintaxe:**
```bash
python3 snakeOps dnsTakeover --domain exemplo.com --wordlist wordlists/subdomains/common.txt
python3 snakeOps dnsTakeover --list subs.txt
```

**Opções principais:**
- `--domain exemplo.com`: domínio base.
- `--wordlist path.txt`: wordlist de **prefixos** de subdomínio (um por linha). Gera `prefixo.dominio`.
- `--list subs.txt`: arquivo com **subdomínios** prontos (um por linha).
- `--signatures-file assinaturas.txt`: estende o dicionário de assinaturas (`provedor|assinatura` por linha).
- `-w, --workers 50`: paralelismo.
- `--host-timeout 6`: timeout p/ `host` (s).
- `--http-timeout 5`: timeout p/ `curl` (s).
- `--scheme {http, https, both}`: onde validar o takeover (padrão `http`).
- `--show-cmd`: mostra os `host`/`curl` executados.

**Exemplos:**
```bash
# modo domínio + wordlist (gera sub.domínio)
python3 snakeOps dnsTakeover --domain exemplo.com --wordlist wordlists/subdomains/common.txt

# lista direta de subdomínios
python3 snakeOps dnsTakeover --list subs.txt

# checar http e https, com workers maiores
python3 snakeOps dnsTakeover --list subs.txt --scheme both -w 100

# ampliar assinaturas
python3 snakeOps dnsTakeover --list subs.txt --signatures-file minhas_assinaturas.txt

# ver os comandos executados
python3 snakeOps dnsTakeover --list subs.txt --show-cmd
```

**Saída (resumo):**
- Para CNAME: mostra a linha de alias e, se bater assinatura de provedor, tenta `curl` e alerta:  
  `⚠️ POSSÍVEL TAKEOVER → provider → 'assinatura' detectada`
- Para A/AAAA: lista IPs marcados como `✅`.

**Barulho / Logs:**
- **Consultas DNS** (visíveis no seu resolver e possivelmente nos autoritativos).
- **Requisições HTTP/HTTPS** ao subdomínio (via `curl`) — geram **logs no servidor/provedor**.
- Use `--workers` com parcimônia para não sobrecarregar nem “sinalizar” atividade agressiva.

---

## Listas e Wordlists

**Domínios (infoDns):**
- Padrão: `data/lists/domains.txt`  
- Alternativa compatível: `dominios.txt` na raiz
- Formato: **um domínio por linha**, pode comentar com `#`.

Exemplo (`data/lists/domains.txt`):
```
# domínios de teste
example.com
meusite.com.br
```

**Subdomínios (dnsTakeover):**
- **Wordlist de prefixos** (modo `--domain`): `wordlists/subdomains/*.txt` ou `data/lists/subdomains.txt`
  - Ex.: `www`, `app`, `cdn`, `blog` … (um por linha).
- **Lista pronta de subdomínios** (modo `--list`): arquivo qualquer, **um subdomínio por linha** (ex.: `app.example.com`).

**Portas (portScan):**
- `--ports-file`: arquivo com **uma porta por linha** ou linhas com faixas/vírgulas, ex.:
```
22
80,443
3000-3010
```

---

## “Barulho” / Logs no alvo (OPSEC)

| Comando      | O que faz “barulho”                                               | Onde loga normalmente                              | Como reduzir barulho                                      |
|--------------|-------------------------------------------------------------------|-----------------------------------------------------|------------------------------------------------------------|
| `infoDns`    | Consultas DNS e tentativas de AXFR                                | Resolver local/ISP/empresa; NS autoritativos (AXFR) | Use `--no-axfr`; limite `--types`; aumente `--sleep`       |
| `portScan`   | Conexões TCP (e GET HTTP se `--banner`)                           | Firewall, IDS/IPS, serviços/servidores              | Diminua `-w`; aumente `-t`; evite `--banner`; use perfis   |
| `dnsTakeover`| DNS + `curl` no subdomínio (HTTP/HTTPS)                           | Resolver + servidor/provedor                        | Ajuste `-w`; `--scheme http`; aumente `--http-timeout`; sem `--show-cmd` |

> **Boas práticas:** tenha autorização, comece pelos perfis/escopos menores, monitore respostas, e documente _rate limits_.

---

## Exemplos rápidos (cola-e-roda)

```bash
# DNS
python3 snakeOps infoDns exemplo.com
python3 snakeOps infoDns -l -f data/lists/domains.txt
python3 snakeOps infoDns exemplo.com --types A AAAA MX TXT NS --no-axfr

# PORTAS
python3 snakeOps portScan 37.59.174.225 --profile leve --banner
python3 snakeOps portScan alvo.com --profile pesado
python3 snakeOps portScan alvo.com --ports 22,80,443 --range 8000-8080 --banner --show-closed

# TAKEOVER
python3 snakeOps dnsTakeover --domain exemplo.com --wordlist wordlists/subdomains/common.txt
python3 snakeOps dnsTakeover --list subs.txt --scheme both -w 100
python3 snakeOps dnsTakeover --list subs.txt --signatures-file minhas_assinaturas.txt --show-cmd
```

---

## Dicas, troubleshooting & FAQ

**“`host: command not found`”**  
Instale `dnsutils` / `bind9-dnsutils` (Linux) ou use a alternativa do seu SO.

**“`curl: command not found`”**  
Instale `curl`. Sem ele, `dnsTakeover` não consegue validar takeover (só mostra CNAME/A/AAAA).

**Time out / resultados lentos**  
- Aumente `--timeout` (portScan) ou `--host-timeout`/`--http-timeout` (dnsTakeover).
- Reduza `-w/--workers` para diminuir paralelismo.
- Em redes com latência alta, adapte os valores.

**Resultados inconsistentes**  
- DNS pode estar em cache. Repetir depois de alguns minutos pode alterar o output.
- `portScan` (atual) resolve apenas **IPv4** — se o host for _apenas IPv6_, pode não alcançar.

**Saídas muito longas**  
- Use filtros (`--types` no infoDns, perfis no portScan, listas menores no dnsTakeover).
- Reduza `--preview` no portScan para cabeçalho mais curto.

**Legalidade/ética**  
- Veja [Avisos legais](#avisos-legais).

---

## Adicionar novos comandos

Crie um arquivo em `snakeops/commands/`:
```python
# snakeops/commands/meu_cmd.py
import argparse
from typing import List

COMMAND_NAME = "meuCmd"
COMMAND_HELP = "Descrição curta do que faz."

def build_arg_parser():
    p = argparse.ArgumentParser(prog="snakeOps meuCmd", description="Detalhes do comando.")
    p.add_argument("alvo", help="Alvo ou parâmetro principal")
    return p

def run(argv: List[str]):
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    print(f"Executando meuCmd para: {args.alvo}")
```

Rode `python3 snakeOps` e o comando aparecerá automaticamente.

---

## Avisos legais

- Use as ferramentas **apenas em alvos autorizados**.  
- Mesmo atividades “passivas” (consultas DNS) podem gerar logs.  
- `portScan` abre conexões TCP; `dnsTakeover` faz requisições HTTP/HTTPS.  
- Você é responsável por **conformidade legal e políticas corporativas**.

---

### Créditos & versão
- **Versão do README:** 1.0  
- Projeto pensado para ser simples, extensível e sem dependências externas.

Boa análise e bons testes! 🚀
