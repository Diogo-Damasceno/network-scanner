import socket
import threading

from netscan.scanner import (
    expand_targets, scan_host_socket, scan_network, _guess_os, Port,
)
from netscan.storage import connect, save_scan
from netscan.report import render_html


def test_expand_cidr():
    ips = expand_targets("192.168.0.0/30")
    assert ips == ["192.168.0.1", "192.168.0.2"]


def test_expand_single_ip():
    assert expand_targets("10.0.0.5") == ["10.0.0.5"]


def test_guess_os():
    assert "Windows" in _guess_os([Port(3389, "rdp")])
    assert "Linux" in _guess_os([Port(22, "ssh")])
    assert _guess_os([]) == "desconhecido"


def _serve_once(port_holder):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port_holder.append(srv.getsockname()[1])
    try:
        conn, _ = srv.accept()
        conn.close()
    except OSError:
        pass
    finally:
        srv.close()


def test_socket_scan_detects_open_port():
    holder: list[int] = []
    t = threading.Thread(target=_serve_once, args=(holder,), daemon=True)
    t.start()
    while not holder:
        pass
    port = holder[0]
    host = scan_host_socket("127.0.0.1", [port], timeout=1.0)
    assert host is not None
    assert any(p.number == port for p in host.ports)


def test_storage_roundtrip():
    from netscan.scanner import Host
    conn = connect(":memory:")
    hosts = [Host(ip="1.2.3.4", ports=[Port(80, "http")])]
    scan_id = save_scan(conn, "1.2.3.4", hosts)
    assert scan_id == 1
    count = conn.execute("SELECT COUNT(*) FROM ports").fetchone()[0]
    assert count == 1


def test_html_report_contains_ip():
    from netscan.scanner import Host
    html = render_html("1.2.3.4", [Host(ip="1.2.3.4", ports=[Port(80, "http")])])
    assert "1.2.3.4" in html
    assert "http" in html
    assert "<html" in html
