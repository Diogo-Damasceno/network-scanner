"""Persistência dos resultados de varredura em SQLite."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from .scanner import Host

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    ip TEXT NOT NULL,
    hostname TEXT,
    os_guess TEXT,
    latency_ms REAL
);
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id INTEGER NOT NULL REFERENCES hosts(id),
    number INTEGER NOT NULL,
    service TEXT,
    banner TEXT
);
"""


def connect(path: str = "scans.db") -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.executescript(_SCHEMA)
    return conn


def save_scan(conn: sqlite3.Connection, target: str, hosts: list[Host]) -> int:
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO scans (target, started_at) VALUES (?, ?)",
        (target, datetime.now(timezone.utc).isoformat()),
    )
    scan_id = cur.lastrowid
    for h in hosts:
        cur.execute(
            "INSERT INTO hosts (scan_id, ip, hostname, os_guess, latency_ms) "
            "VALUES (?, ?, ?, ?, ?)",
            (scan_id, h.ip, h.hostname, h.os_guess, h.latency_ms),
        )
        host_id = cur.lastrowid
        for p in h.ports:
            cur.execute(
                "INSERT INTO ports (host_id, number, service, banner) VALUES (?, ?, ?, ?)",
                (host_id, p.number, p.service, p.banner),
            )
    conn.commit()
    return scan_id
