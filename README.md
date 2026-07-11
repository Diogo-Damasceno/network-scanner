# network-scanner

Scanner de rede inteligente que descobre dispositivos, identifica portas abertas,
tenta adivinhar o sistema operacional e gera um **relatório HTML** — com
armazenamento em **SQLite** para histórico de varreduras.

> ⚠️ Ferramenta educacional. Faça varreduras **apenas em redes que você possui ou
> tem autorização explícita**. Escanear redes de terceiros é ilegal.

## Instalação

Pré-requisitos: **Python 3.10+**.

```bash
git clone https://github.com/Diogo-Damasceno/network-scanner.git
cd network-scanner
python3 -m venv .venv
. .venv/bin/activate
pip install -e .
```

Após instalar, o comando do projeto fica disponível dentro do venv.
Para usar fora dele, crie um atalho:

```bash
mkdir -p ~/.local/bin
ln -sf "$(pwd)/.venv/bin/netscan" ~/.local/bin/netscan
```

> Dica: se `~/.local/bin` não estiver no teu `PATH`, rode
> `export PATH="$HOME/.local/bin:$PATH"` (e adicione ao `~/.bashrc`/`~/.zshrc`).


## Uso

```bash
# varre uma subrede (CIDR)
netscan 192.168.0.0/24

# portas especificas + relatorio HTML
netscan 10.0.0.5 -p 22,80,443 --html relatorio.html

# forca fallback em socket (sem nmap)
netscan 192.168.0.0/24 --no-nmap
```

## Licença

MIT — veja `LICENSE`.
