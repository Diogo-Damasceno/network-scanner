"""CLI do Network Scanner."""

from __future__ import annotations

import argparse
import sys

from .scanner import scan_network, has_nmap, COMMON_PORTS
from .storage import connect, save_scan
from .report import write_report

try:
    from rich.console import Console
    from rich.table import Table
    _RICH = True
except ImportError:
    _RICH = False


def _parse_ports(spec: str | None) -> list[int]:
    if not spec:
        return list(COMMON_PORTS)
    ports: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            ports.extend(range(int(a), int(b) + 1))
        else:
            ports.append(int(part))
    return ports


def _print_plain(hosts):
    for h in hosts:
        print(f"\n{h.ip} ({h.hostname or 'sem DNS'}) — {h.os_guess} — {h.latency_ms}ms")
        for p in h.ports:
            print(f"  {p.number:>5}/tcp  {p.service:<12} {p.banner}")


def _print_rich(hosts):
    console = Console()
    for h in hosts:
        table = Table(title=f"{h.ip}  ·  {h.hostname or 'sem DNS'}  ·  {h.os_guess}  ·  {h.latency_ms}ms")
        table.add_column("Porta", style="cyan", justify="right")
        table.add_column("Serviço", style="green")
        table.add_column("Banner", style="yellow")
        for p in h.ports:
            table.add_row(str(p.number), p.service, p.banner or "—")
        console.print(table)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scanner de rede: descobre hosts, portas, SO e gera relatório HTML."
    )
    parser.add_argument("target", help="IP, CIDR (192.168.0.0/24) ou hostname")
    parser.add_argument("-p", "--ports", help="portas: '22,80,443' ou '1-1024'")
    parser.add_argument("--no-nmap", action="store_true", help="força fallback em socket")
    parser.add_argument("--html", help="caminho do relatório HTML de saída")
    parser.add_argument("--db", default="scans.db", help="arquivo SQLite (padrão: scans.db)")
    parser.add_argument("--timeout", type=float, default=0.5, help="timeout por porta (s)")
    args = parser.parse_args(argv)

    ports = _parse_ports(args.ports)
    backend = "socket" if (args.no_nmap or not has_nmap()) else "nmap"
    print(f"[*] Varrendo {args.target} · {len(ports)} portas · backend={backend}",
          file=sys.stderr)

    hosts = scan_network(args.target, ports=ports,
                         use_nmap=None if not args.no_nmap else False,
                         timeout=args.timeout)

    print(f"[*] {len(hosts)} host(s) vivo(s) encontrado(s).", file=sys.stderr)

    if _RICH:
        _print_rich(hosts)
    else:
        _print_plain(hosts)

    conn = connect(args.db)
    scan_id = save_scan(conn, args.target, hosts)
    print(f"[*] Resultados salvos em {args.db} (scan #{scan_id}).", file=sys.stderr)

    if args.html:
        write_report(args.html, args.target, hosts)
        print(f"[*] Relatório HTML: {args.html}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
