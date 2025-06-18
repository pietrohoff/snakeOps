
# 🐍 SnakeOps

**SnakeOps** é uma coleção de ferramentas simples e eficazes para testes de segurança ofensiva (pentest), desenvolvidas em Python.

---

## 📦 Ferramentas incluídas

### 🔎 dnsRes.py
- **Função:** Resolve o IP de um domínio.
- **Extra:** Verifica subdomínios comuns e permite iniciar um port scan diretamente.
- **Uso:**
  ```bash
  python3 dnsRes.py exemplo.com
  ```

### 🚪 portScan.py
- **Função:** Realiza varredura de portas (1 a 100) em um IP.
- **Modo banner:** Tenta capturar banners dos serviços encontrados.
- **Uso:**
  ```bash
  python3 portScan.py 192.168.0.1 true
  ```

---

## 📚 Pré-requisitos

- Python 3.x
- Permissões de rede (para executar port scan em algumas redes pode ser necessário sudo)

---

## 🛠 Como usar

1. Clone o repositório:
   ```bash
   git clone https://github.com/seu-usuario/snakeOps.git
   cd snakeOps
   ```

2. Torne os arquivos executáveis:
   ```bash
   chmod +x *.py
   ```

3. Execute:
   ```bash
   python3 dnsRes.py alvo.com
   ```

