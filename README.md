# Network Scanner 🛰️

Scanner de rede inteligente que descobre dispositivos, identifica portas abertas, tenta adivinhar o sistema operacional e gera um **relatório HTML** — com armazenamento em **SQLite** para histórico de varreduras.

> ⚠️ Ferramenta educacional. Faça varreduras **apenas em redes que você possui ou tem autorização explícita para testar**. Escanear redes de terceiros sem permissão é ilegal na maioria dos países.

## Recursos

- Descoberta de hosts vivos em IP, **CIDR** (`192.168.0.0/24`) ou hostname
- Varredura de portas concorrente (multithread)
- Dois backends: **nmap** (se instalado) ou **fallback puro em Python (socket)** — funciona sem root e sem nmap
- Captura de **banners** e heurística de detecção de SO
- Histórico persistente em **SQLite**
- **Relatório HTML** autocontido com tema escuro
- Saída bonita no terminal com **Rich**

## Instalação

```bash
git clone https://github.com/Diogo-Damasceno/network-scanner.git
cd network-scanner
pip install -e .
```

## Uso

```bash
# varrer a rede local, portas comuns, gerar HTML
netscan 192.168.1.0/24 --html relatorio.html

# portas específicas ou faixa
netscan 192.168.1.10 -p 22,80,443
netscan 192.168.1.10 -p 1-1024

# forçar o fallback em socket (sem nmap)
netscan 192.168.1.0/24 --no-nmap

# escolher o arquivo de banco
netscan 10.0.0.0/28 --db minhas_varreduras.db
```

## Testes

```bash
pip install -e '.[dev]'
pytest -q
```

## Arquitetura

```
netscan/
├── scanner.py   # descoberta + varredura (nmap e socket)
├── storage.py   # persistência SQLite
├── report.py    # geração de HTML
└── cli.py       # interface de linha de comando (Rich)
```

## Licença

MIT
