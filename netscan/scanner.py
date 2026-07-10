"""Descoberta de hosts e varredura de portas.

Funciona em dois modos:
  * nmap (se instalado): descoberta e detecção de SO mais ricas.
  * fallback puro em Python (socket): funciona sem nmap e sem root.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field

# Portas comuns e o serviço associado (fallback quando não há nmap).
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios",
    143: "imap", 443: "https", 445: "smb", 993: "imaps", 995: "pop3s",
    1723: "pptp", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    27017: "mongodb",
}


@dataclass
class Port:
    number: int
    service: str
    banner: str = ""


@dataclass
class Host:
    ip: str
    hostname: str = ""
    mac: str = ""
    os_guess: str = ""
    latency_ms: float = 0.0
    ports: list[Port] = field(default_factory=list)


def has_nmap() -> bool:
    return shutil.which("nmap") is not None


def expand_targets(target: str) -> list[str]:
    """Aceita IP único, CIDR (192.168.0.0/24) ou hostname."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        if net.num_addresses > 1:
            return [str(h) for h in net.hosts()]
        return [str(net.network_address)]
    except ValueError:
        # provavelmente hostname
        return [socket.gethostbyname(target)]


# --------------------------- fallback em socket ---------------------------

def _ping_tcp(ip: str, timeout: float = 0.5) -> float | None:
    """Estima 'vivo' tentando conectar em portas comuns. Retorna latência ms."""
    for port in (80, 443, 22, 445, 3389):
        start = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return (time.perf_counter() - start) * 1000
        except OSError:
            continue
    return None


def _scan_port(ip: str, port: int, timeout: float = 0.5) -> Port | None:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = ""
            try:
                sock.settimeout(0.5)
                banner = sock.recv(128).decode("latin-1", "ignore").strip()
            except OSError:
                pass
            return Port(number=port, service=COMMON_PORTS.get(port, "unknown"), banner=banner)
    except OSError:
        return None


def _reverse_dns(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except OSError:
        return ""


def scan_host_socket(ip: str, ports: list[int], timeout: float = 0.5,
                     workers: int = 100) -> Host | None:
    latency = _ping_tcp(ip, timeout)
    open_ports: list[Port] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_scan_port, ip, p, timeout): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            res = fut.result()
            if res:
                open_ports.append(res)
    if latency is None and not open_ports:
        return None  # host provavelmente offline
    open_ports.sort(key=lambda p: p.number)
    return Host(
        ip=ip,
        hostname=_reverse_dns(ip),
        os_guess=_guess_os(open_ports),
        latency_ms=round(latency or 0.0, 2),
        ports=open_ports,
    )


def _guess_os(ports: list[Port]) -> str:
    """Heurística simples de SO a partir das portas/banners."""
    nums = {p.number for p in ports}
    banners = " ".join(p.banner.lower() for p in ports)
    if 3389 in nums or 445 in nums or 135 in nums:
        return "Windows (provável)"
    if "ubuntu" in banners:
        return "Linux/Ubuntu"
    if "debian" in banners:
        return "Linux/Debian"
    if 22 in nums:
        return "Linux/Unix (provável)"
    return "desconhecido"


# --------------------------- backend nmap ---------------------------

def scan_host_nmap(ip: str, ports: list[int], timeout: int = 60) -> Host | None:
    port_arg = ",".join(str(p) for p in ports)
    try:
        out = subprocess.run(
            ["nmap", "-sT", "-Pn", "--open", "-p", port_arg, "-oG", "-", ip],
            capture_output=True, text=True, timeout=timeout,
        ).stdout
    except (subprocess.SubprocessError, OSError):
        return None
    open_ports: list[Port] = []
    for line in out.splitlines():
        if "Ports:" in line:
            seg = line.split("Ports:")[1]
            for entry in seg.split(","):
                parts = entry.strip().split("/")
                if len(parts) >= 5 and parts[1] == "open":
                    num = int(parts[0])
                    svc = parts[4] or COMMON_PORTS.get(num, "unknown")
                    open_ports.append(Port(number=num, service=svc))
    if not open_ports:
        return None
    open_ports.sort(key=lambda p: p.number)
    return Host(ip=ip, hostname=_reverse_dns(ip), os_guess=_guess_os(open_ports),
                ports=open_ports)


def scan_network(target: str, ports: list[int] | None = None,
                 use_nmap: bool | None = None, timeout: float = 0.5,
                 max_host_workers: int = 50) -> list[Host]:
    """Varre um alvo (IP/CIDR/hostname) e retorna hosts vivos com portas abertas."""
    ports = ports or list(COMMON_PORTS)
    if use_nmap is None:
        use_nmap = has_nmap()
    ips = expand_targets(target)

    def _scan(ip: str) -> Host | None:
        if use_nmap:
            return scan_host_nmap(ip, ports)
        return scan_host_socket(ip, ports, timeout)

    results: list[Host] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_host_workers) as ex:
        for host in ex.map(_scan, ips):
            if host:
                results.append(host)
    results.sort(key=lambda h: tuple(int(o) for o in h.ip.split(".")))
    return results
