"""Gera relatório HTML autocontido a partir dos hosts varridos."""

from __future__ import annotations

import html
from datetime import datetime

from .scanner import Host

_CSS = """
body{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;margin:0;padding:2rem}
h1{color:#58a6ff}.meta{color:#8b949e;margin-bottom:1.5rem}
.host{background:#161b22;border:1px solid #30363d;border-radius:8px;margin:1rem 0;padding:1rem}
.host h2{margin:0 0 .5rem;color:#7ee787;font-size:1.1rem}
.tag{display:inline-block;background:#21262d;border-radius:4px;padding:2px 8px;margin-right:6px;font-size:.8rem}
table{width:100%;border-collapse:collapse;margin-top:.5rem}
th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #30363d;font-size:.9rem}
th{color:#8b949e}.port{color:#ffa657;font-weight:bold}
.empty{color:#8b949e}
"""


def render_html(target: str, hosts: list[Host]) -> str:
    rows = []
    for h in hosts:
        port_rows = "".join(
            f"<tr><td class='port'>{p.number}</td><td>{html.escape(p.service)}</td>"
            f"<td>{html.escape(p.banner) or '—'}</td></tr>"
            for p in h.ports
        ) or "<tr><td colspan='3' class='empty'>nenhuma porta aberta</td></tr>"
        rows.append(f"""
        <div class="host">
          <h2>{html.escape(h.ip)}{' · ' + html.escape(h.hostname) if h.hostname else ''}</h2>
          <span class="tag">SO: {html.escape(h.os_guess or '?')}</span>
          <span class="tag">latência: {h.latency_ms} ms</span>
          <span class="tag">{len(h.ports)} porta(s)</span>
          <table><tr><th>Porta</th><th>Serviço</th><th>Banner</th></tr>{port_rows}</table>
        </div>""")

    body = "".join(rows) or "<p class='empty'>Nenhum host vivo encontrado.</p>"
    return f"""<!DOCTYPE html><html lang="pt-br"><head><meta charset="utf-8">
<title>Relatório de Varredura — {html.escape(target)}</title><style>{_CSS}</style></head>
<body><h1>🛰️ Relatório de Varredura de Rede</h1>
<div class="meta">Alvo: <b>{html.escape(target)}</b> · {len(hosts)} host(s) vivo(s) ·
Gerado em {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
{body}</body></html>"""


def write_report(path: str, target: str, hosts: list[Host]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(target, hosts))
